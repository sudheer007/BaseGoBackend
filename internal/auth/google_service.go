package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gobackend/internal/audit"
	"gobackend/internal/config"
	"gobackend/internal/models"

	"github.com/go-pg/pg/v10"
	"github.com/google/uuid"

	"google.golang.org/api/idtoken"
)

var (
	ErrInvalidGoogleToken = errors.New("invalid Google ID token")
	ErrGoogleAuthFailed   = errors.New("Google authentication failed")
)

// GoogleTokenRequest represents the request for Google token verification
type GoogleTokenRequest struct {
	Token string `json:"token" binding:"required"`
}

// GoogleService provides Google authentication functionality
type GoogleService struct {
	db       *pg.DB
	config   *config.Config
	auditSvc *audit.Service
	AuthSvc  *Service
}

// NewGoogleService creates a new Google authentication service
func NewGoogleService(db *pg.DB, cfg *config.Config, auditSvc *audit.Service, authSvc *Service) *GoogleService {
	return &GoogleService{
		db:       db,
		config:   cfg,
		auditSvc: auditSvc,
		AuthSvc:  authSvc,
	}
}

// GoogleLogin authenticates a user with a Google ID token
func (s *GoogleService) GoogleLogin(ctx context.Context, req GoogleTokenRequest, ipAddress, userAgent string) (*TokenResponse, error) {
	// Verify Google ID token
	payload, err := s.verifyGoogleToken(ctx, req.Token)
	if err != nil {
		s.auditSvc.LogEvent(ctx, "google_login_failed", map[string]interface{}{
			"error":      err.Error(),
			"ip_address": ipAddress,
			"user_agent": userAgent,
		})
		return nil, ErrInvalidGoogleToken
	}

	// Extract user info from the payload
	email := payload.Claims["email"].(string)
	if email == "" {
		s.auditSvc.LogEvent(ctx, "google_login_failed", map[string]interface{}{
			"reason":     "no_email",
			"ip_address": ipAddress,
			"user_agent": userAgent,
		})
		return nil, ErrGoogleAuthFailed
	}

	// Check if user exists in our system
	user := new(models.User)
	err = s.db.Model(user).
		Where("email = ?", email).
		Relation("Tenant").
		Select()

	if err != nil {
		if errors.Is(err, pg.ErrNoRows) {
			// User doesn't exist, create new user
			return s.createUserFromGoogle(ctx, payload, ipAddress, userAgent)
		}
		return nil, fmt.Errorf("database error: %w", err)
	}

	// User exists, check if account is active
	if !user.Active {
		s.auditSvc.LogEvent(ctx, "google_login_failed", map[string]interface{}{
			"reason":     "account_inactive",
			"user_id":    user.ID.String(),
			"tenant_id":  user.TenantID.String(),
			"ip_address": ipAddress,
			"user_agent": userAgent,
		})
		return nil, ErrUserNotActive
	}

	// Generate tokens
	accessTokenExp := time.Now().Add(s.config.JWT.ExpiryDuration)
	refreshTokenExp := time.Now().Add(s.config.JWT.RefreshExpiry)

	tokenID := uuid.New().String()

	// Create access token
	accessToken, err := s.AuthSvc.generateAccessToken(user, accessTokenExp)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Create refresh token
	refreshToken, err := s.AuthSvc.generateRefreshToken(user.ID.String(), tokenID, refreshTokenExp)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Store refresh token in database
	token := &models.RefreshToken{
		ID:        uuid.New(),
		UserID:    user.ID,
		TokenID:   tokenID,
		ExpiresAt: refreshTokenExp,
		CreatedAt: time.Now(),
		IPAddress: ipAddress,
		UserAgent: userAgent,
	}

	_, err = s.db.Model(token).Insert()
	if err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	// Log successful login
	s.auditSvc.LogEvent(ctx, "google_login_success", map[string]interface{}{
		"user_id":    user.ID.String(),
		"tenant_id":  user.TenantID.String(),
		"ip_address": ipAddress,
		"user_agent": userAgent,
	})

	// Update last login timestamp
	_, err = s.db.Model(user).
		Set("last_login = ?", time.Now()).
		Where("id = ?", user.ID).
		Update()
	if err != nil {
		// Non-critical error, just log it
		fmt.Printf("Error updating last login: %v\n", err)
	}

	// Return token response
	return &TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    accessTokenExp.Unix(),
		TokenType:    "Bearer",
		UserID:       user.ID.String(),
		TenantID:     user.TenantID.String(),
	}, nil
}

// verifyGoogleToken verifies a Google ID token and returns the payload
func (s *GoogleService) verifyGoogleToken(ctx context.Context, idToken string) (*idtoken.Payload, error) {
	// Use the client ID from config
	clientID := s.config.OAuth.Google.ClientID

	// Verify the ID token
	payload, err := idtoken.Validate(ctx, idToken, clientID)
	if err != nil {
		return nil, fmt.Errorf("invalid Google ID token: %w", err)
	}

	return payload, nil
}

// createUserFromGoogle creates a new user from Google profile information
func (s *GoogleService) createUserFromGoogle(ctx context.Context, payload *idtoken.Payload, ipAddress, userAgent string) (*TokenResponse, error) {
	// Extract user info
	email := payload.Claims["email"].(string)
	name := ""
	if payload.Claims["name"] != nil {
		name = payload.Claims["name"].(string)
	}

	// Create a new user with Google info
	user := &models.User{
		ID:           uuid.New(),
		Email:        email,
		FirstName:    name,            // We might want to split name into first and last
		LastName:     "",              // Google might provide given_name and family_name separately
		PasswordHash: "",              // No password for Google users
		Role:         models.RoleUser, // Default role
		Active:       true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		LastLogin:    time.Now(),
		GoogleID:     payload.Subject, // Store Google's user ID
	}

	// Add default tenant if needed
	if s.config.Multitenancy.Enabled {
		// Use default tenant from config
		user.TenantID = uuid.MustParse(s.config.Multitenancy.DefaultTenantID)
	} else {
		// Use a default UUID for single-tenant mode
		user.TenantID = uuid.MustParse("00000000-0000-0000-0000-000000000001")
	}

	// Insert the new user
	_, err := s.db.Model(user).Insert()
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Log user creation
	s.auditSvc.LogEvent(ctx, "user_created", map[string]interface{}{
		"source":     "google_auth",
		"user_id":    user.ID.String(),
		"tenant_id":  user.TenantID.String(),
		"ip_address": ipAddress,
		"user_agent": userAgent,
	})

	// Generate tokens for the new user
	accessTokenExp := time.Now().Add(s.config.JWT.ExpiryDuration)
	refreshTokenExp := time.Now().Add(s.config.JWT.RefreshExpiry)

	tokenID := uuid.New().String()

	// Create access token
	accessToken, err := s.AuthSvc.generateAccessToken(user, accessTokenExp)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Create refresh token
	refreshToken, err := s.AuthSvc.generateRefreshToken(user.ID.String(), tokenID, refreshTokenExp)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Store refresh token in database
	token := &models.RefreshToken{
		ID:        uuid.New(),
		UserID:    user.ID,
		TokenID:   tokenID,
		ExpiresAt: refreshTokenExp,
		CreatedAt: time.Now(),
		IPAddress: ipAddress,
		UserAgent: userAgent,
	}

	_, err = s.db.Model(token).Insert()
	if err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	// Log successful login
	s.auditSvc.LogEvent(ctx, "google_signup_login_success", map[string]interface{}{
		"user_id":    user.ID.String(),
		"tenant_id":  user.TenantID.String(),
		"ip_address": ipAddress,
		"user_agent": userAgent,
	})

	// Return token response
	return &TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    accessTokenExp.Unix(),
		TokenType:    "Bearer",
		UserID:       user.ID.String(),
		TenantID:     user.TenantID.String(),
	}, nil
}

// GetUserFromToken extracts user information from a validated token
func (s *GoogleService) GetUserFromToken(ctx context.Context, userID string) (*models.User, error) {
	// Validate user ID
	if userID == "" {
		return nil, errors.New("invalid user ID")
	}

	parsedID, err := uuid.Parse(userID)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID format: %w", err)
	}

	// Fetch user from database
	user := new(models.User)
	err = s.db.Model(user).
		Where("id = ?", parsedID).
		Select()

	if err != nil {
		if errors.Is(err, pg.ErrNoRows) {
			return nil, errors.New("user not found")
		}
		return nil, fmt.Errorf("database error: %w", err)
	}

	return user, nil
}
