package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-pg/pg/v10"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gobackend/internal/audit"
	"gobackend/internal/config"
	"gobackend/internal/models"
)

var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrUserNotActive      = errors.New("user account is not active")
	ErrUserLocked         = errors.New("user account is locked")
	ErrInvalidToken       = errors.New("invalid or expired token")
	ErrInvalidRefreshToken = errors.New("invalid or expired refresh token")
	ErrMaxLoginAttempts   = errors.New("maximum login attempts exceeded")
	ErrEmailAlreadyExists = errors.New("email already exists")
	ErrInvalidEmail       = errors.New("invalid email format")
	ErrInvalidPassword    = errors.New("password must be at least 8 characters")
	ErrTenantNotFound     = errors.New("tenant not found")
	ErrOrganizationNotFound = errors.New("organization not found")
)

// Claims represents the JWT claims for authentication
type Claims struct {
	UserID   string `json:"user_id"`
	TenantID string `json:"tenant_id"`
	Email    string `json:"email"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// RefreshClaims represents the JWT claims for refresh tokens
type RefreshClaims struct {
	UserID   string `json:"user_id"`
	TokenID  string `json:"token_id"`
	jwt.RegisteredClaims
}

// LoginRequest represents the data needed for login
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
	MFAToken string `json:"mfa_token"`
}

// TokenResponse represents the response with authentication tokens
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"`
	TokenType    string `json:"token_type"`
	UserID       string `json:"user_id"`
	TenantID     string `json:"tenant_id"`
	RequiresMFA  bool   `json:"requires_mfa,omitempty"`
}

// SignupRequest represents the data needed for user registration
type SignupRequest struct {
	Email           string    `json:"email" binding:"required,email"`
	Password        string    `json:"password" binding:"required,min=8"`
	FirstName       string    `json:"first_name"`
	LastName        string    `json:"last_name"`
	OrganizationID  uuid.UUID `json:"organization_id,omitempty"`
	TenantID        uuid.UUID `json:"tenant_id,omitempty"`
	Role            string    `json:"role,omitempty"` // Optional, defaults to RoleUser
}

// Service provides authentication functionality
type Service struct {
	db          *pg.DB
	config      *config.Config
	auditSvc    *audit.Service
	maxAttempts int
	lockDuration time.Duration
}

// NewService creates a new authentication service
func NewService(db *pg.DB, cfg *config.Config, auditSvc *audit.Service) *Service {
	return &Service{
		db:          db,
		config:      cfg,
		auditSvc:    auditSvc,
		maxAttempts: 5, // Default to 5 max attempts
		lockDuration: 15 * time.Minute, // Default to 15 minutes
	}
}

// Login authenticates a user and returns authentication tokens
func (s *Service) Login(ctx context.Context, req LoginRequest, ipAddress, userAgent string) (*TokenResponse, error) {
	// Get user by email
	user := new(models.User)
	err := s.db.Model(user).
		Where("email = ?", req.Email).
		Relation("Tenant").
		Select()
	
	if err != nil {
		if errors.Is(err, pg.ErrNoRows) {
			// Record failed login attempt but return a generic error
			s.auditSvc.LogFailure(ctx, uuid.Nil, uuid.Nil, models.AuditActionLogin, 
				"auth", "", fmt.Sprintf("Failed login attempt for %s", req.Email), 
				"user not found", ipAddress, userAgent)
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("database error: %w", err)
	}

	// Check if account is active
	if !user.Active {
		s.auditSvc.LogFailure(ctx, user.TenantID, user.ID, models.AuditActionLogin, 
			"auth", user.ID.String(), "Inactive account login attempt", 
			"account not active", ipAddress, userAgent)
		return nil, ErrUserNotActive
	}

	// Check if account is locked
	if user.IsLocked() {
		s.auditSvc.LogFailure(ctx, user.TenantID, user.ID, models.AuditActionLogin, 
			"auth", user.ID.String(), "Locked account login attempt", 
			"account locked", ipAddress, userAgent)
		return nil, ErrUserLocked
	}

	// Verify password
	if !user.CheckPassword(req.Password) {
		// Increment failed login attempts
		user.FailedAttempts++
		
		// Lock account if max attempts are reached
		if user.FailedAttempts >= s.maxAttempts {
			user.LockedUntil = time.Now().Add(s.lockDuration)
			s.auditSvc.LogFailure(ctx, user.TenantID, user.ID, models.AuditActionLogin, 
				"auth", user.ID.String(), "Account locked due to too many failed attempts", 
				"max attempts exceeded", ipAddress, userAgent)
		}
		
		// Update the user record
		_, err = s.db.Model(user).
			Set("failed_attempts = ?", user.FailedAttempts).
			Set("locked_until = ?", user.LockedUntil).
			Where("id = ?", user.ID).
			Update()
		if err != nil {
			return nil, fmt.Errorf("failed to update user: %w", err)
		}
		
		s.auditSvc.LogFailure(ctx, user.TenantID, user.ID, models.AuditActionLogin, 
			"auth", user.ID.String(), "Failed login attempt", 
			"invalid password", ipAddress, userAgent)
		return nil, ErrInvalidCredentials
	}

	// Check for MFA if enabled
	if user.MFAEnabled {
		// If MFA is required but not provided or invalid
		if req.MFAToken == "" {
			return &TokenResponse{
				RequiresMFA: true,
				UserID:      user.ID.String(),
				TenantID:    user.TenantID.String(),
			}, nil
		}
		
		// TODO: Implement actual MFA validation
		// For now we're skipping actual implementation
		// if !ValidateMFAToken(user.MFASecret, req.MFAToken) {
		//    s.auditSvc.LogFailure(...)
		//    return nil, errors.New("invalid MFA token")
		// }
	}

	// Reset failed attempts on successful login
	_, err = s.db.Model(user).
		Set("failed_attempts = 0").
		Set("locked_until = NULL").
		Set("last_login = ?", time.Now()).
		Where("id = ?", user.ID).
		Update()
	if err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	// Generate tokens
	accessTokenExp := time.Now().Add(s.config.JWT.ExpiryDuration)
	refreshTokenExp := time.Now().Add(s.config.JWT.RefreshExpiry)
	
	tokenID := uuid.New().String()

	// Create access token
	accessToken, err := s.generateAccessToken(user, accessTokenExp)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Create refresh token
	refreshToken, err := s.generateRefreshToken(user.ID.String(), tokenID, refreshTokenExp)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Log successful login
	s.auditSvc.LogAction(ctx, user.TenantID, user.ID, models.AuditActionLogin, 
		"auth", user.ID.String(), "Successful login", 
		ipAddress, userAgent)

	// Return the token response
	return &TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    accessTokenExp.Unix(),
		TokenType:    "Bearer",
		UserID:       user.ID.String(),
		TenantID:     user.TenantID.String(),
	}, nil
}

// Refresh refreshes an access token using a refresh token
func (s *Service) Refresh(ctx context.Context, refreshToken, ipAddress, userAgent string) (*TokenResponse, error) {
	// Parse the refresh token
	token, err := jwt.ParseWithClaims(refreshToken, &RefreshClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.config.JWT.Secret), nil
	})
	
	if err != nil || !token.Valid {
		return nil, ErrInvalidRefreshToken
	}
	
	// Extract claims
	claims, ok := token.Claims.(*RefreshClaims)
	if !ok {
		return nil, ErrInvalidRefreshToken
	}
	
	// Convert user ID from string to UUID
	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		return nil, err
	}
	
	// Get the user
	user := new(models.User)
	err = s.db.Model(user).
		Where("id = ?", userID).
		Relation("Tenant").
		Select()
	
	if err != nil {
		if errors.Is(err, pg.ErrNoRows) {
			return nil, ErrInvalidRefreshToken
		}
		return nil, fmt.Errorf("database error: %w", err)
	}
	
	// Check if user is active
	if !user.Active {
		s.auditSvc.LogFailure(ctx, user.TenantID, user.ID, models.AuditActionLogin, 
			"auth", user.ID.String(), "Token refresh attempt for inactive account", 
			"account not active", ipAddress, userAgent)
		return nil, ErrUserNotActive
	}
	
	// Generate new tokens
	accessTokenExp := time.Now().Add(s.config.JWT.ExpiryDuration)
	refreshTokenExp := time.Now().Add(s.config.JWT.RefreshExpiry)
	
	newTokenID := uuid.New().String()
	
	// Create access token
	accessToken, err := s.generateAccessToken(user, accessTokenExp)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}
	
	// Create refresh token
	newRefreshToken, err := s.generateRefreshToken(user.ID.String(), newTokenID, refreshTokenExp)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}
	
	// Log token refresh
	s.auditSvc.LogAction(ctx, user.TenantID, user.ID, models.AuditActionLogin, 
		"auth", user.ID.String(), "Token refresh", 
		ipAddress, userAgent)
	
	// Return the token response
	return &TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		ExpiresAt:    accessTokenExp.Unix(),
		TokenType:    "Bearer",
		UserID:       user.ID.String(),
		TenantID:     user.TenantID.String(),
	}, nil
}

// ValidateToken validates the access token and returns the claims
func (s *Service) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.config.JWT.Secret), nil
	})
	
	if err != nil || !token.Valid {
		return nil, ErrInvalidToken
	}
	
	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, ErrInvalidToken
	}
	
	return claims, nil
}

// generateAccessToken creates a JWT access token
func (s *Service) generateAccessToken(user *models.User, expiresAt time.Time) (string, error) {
	claims := &Claims{
		UserID:   user.ID.String(),
		TenantID: user.TenantID.String(),
		Email:    user.Email,
		Role:     string(user.Role),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    s.config.App.Name,
			Subject:   user.ID.String(),
		},
	}
	
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.config.JWT.Secret))
}

// generateRefreshToken creates a JWT refresh token
func (s *Service) generateRefreshToken(userID, tokenID string, expiresAt time.Time) (string, error) {
	claims := &RefreshClaims{
		UserID:   userID,
		TokenID:  tokenID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    s.config.App.Name,
			Subject:   userID,
			ID:        tokenID,
		},
	}
	
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.config.JWT.Secret))
}

// Logout invalidates a user's tokens
func (s *Service) Logout(ctx context.Context, userID uuid.UUID, ipAddress, userAgent string) error {
	// Get the user to get tenant ID for audit log
	user := new(models.User)
	err := s.db.Model(user).
		Where("id = ?", userID).
		Select()
	
	if err != nil && !errors.Is(err, pg.ErrNoRows) {
		return fmt.Errorf("database error: %w", err)
	}
	
	var tenantID uuid.UUID
	if user != nil {
		tenantID = user.TenantID
	}
	
	// Log logout action
	s.auditSvc.LogAction(ctx, tenantID, userID, models.AuditActionLogout, 
		"auth", userID.String(), "User logout", 
		ipAddress, userAgent)
	
	// Note: In a real implementation, you would add the token to a blacklist
	// or revoke specific tokens. For simplicity, we're just logging the action.
	
	return nil
}

// Signup registers a new user and returns authentication tokens
func (s *Service) Signup(ctx context.Context, req SignupRequest, ipAddress, userAgent string) (*TokenResponse, error) {
	// Start a transaction
	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback()
	
	// Validate email format
	if req.Email == "" {
		return nil, ErrInvalidEmail
	}
	
	// Validate password strength
	if len(req.Password) < 8 {
		return nil, ErrInvalidPassword
	}
	
	// Check if email already exists
	exists, err := tx.Model((*models.User)(nil)).
		Where("email = ?", req.Email).
		Exists()
	if err != nil {
		return nil, fmt.Errorf("failed to check email existence: %w", err)
	}
	if exists {
		return nil, ErrEmailAlreadyExists
	}
	
	// Set default role if not provided
	role := models.Role(req.Role)
	if role == "" {
		role = models.RoleUser
	}
	
	// Create new user
	user := &models.User{
		Email:         req.Email,
		Password:      req.Password, // Will be hashed by BeforeInsert hook
		FirstName:     req.FirstName,
		LastName:      req.LastName,
		Role:          role,
		Status:        models.UserStatusActive,
		Active:        true,
		TenantID:      req.TenantID,
		OrganizationID: req.OrganizationID,
	}
	
	// Validate tenant if provided
	if user.TenantID != uuid.Nil {
		tenant := new(models.Tenant)
		err := tx.Model(tenant).Where("id = ?", user.TenantID).Select()
		if err != nil {
			if errors.Is(err, pg.ErrNoRows) {
				return nil, ErrTenantNotFound
			}
			return nil, fmt.Errorf("failed to check tenant: %w", err)
		}
	} else {
		// Use default tenant
		tenant := new(models.Tenant)
		err := tx.Model(tenant).Where("name = ?", "default").Select()
		if err != nil {
			if errors.Is(err, pg.ErrNoRows) {
				// Create default tenant if it doesn't exist
				tenant = &models.Tenant{
					ID:       uuid.New(),
					Name:     "default",
					Domain:   "default.example.com",
					Active:   true,
					Settings: models.Settings{},
				}
				_, err = tx.Model(tenant).Insert()
				if err != nil {
					return nil, fmt.Errorf("failed to create default tenant: %w", err)
				}
			} else {
				return nil, fmt.Errorf("failed to check default tenant: %w", err)
			}
		}
		user.TenantID = tenant.ID
	}
	
	// Validate organization if provided
	if user.OrganizationID != uuid.Nil {
		org := new(models.Organization)
		err := tx.Model(org).Where("id = ?", user.OrganizationID).Select()
		if err != nil {
			if errors.Is(err, pg.ErrNoRows) {
				return nil, ErrOrganizationNotFound
			}
			return nil, fmt.Errorf("failed to check organization: %w", err)
		}
	}
	
	// Insert user
	_, err = tx.Model(user).Insert()
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}
	
	// Generate tokens
	accessTokenExp := time.Now().Add(s.config.JWT.ExpiryDuration)
	refreshTokenExp := time.Now().Add(s.config.JWT.RefreshExpiry)
	
	tokenID := uuid.New().String()
	
	// Create access token
	accessToken, err := s.generateAccessToken(user, accessTokenExp)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}
	
	// Create refresh token
	refreshToken, err := s.generateRefreshToken(user.ID.String(), tokenID, refreshTokenExp)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}
	
	// Log user creation
	s.auditSvc.LogAction(ctx, user.TenantID, user.ID, models.AuditActionCreate, 
		"user", user.ID.String(), "User created through signup", 
		ipAddress, userAgent)
	
	// Commit transaction
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}
	
	// Return the token response
	return &TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    accessTokenExp.Unix(),
		TokenType:    "Bearer",
		UserID:       user.ID.String(),
		TenantID:     user.TenantID.String(),
	}, nil
}

// UpdateUserRole updates a user's role
func (s *Service) UpdateUserRole(ctx context.Context, userID uuid.UUID, role models.Role, updaterID uuid.UUID, ipAddress, userAgent string) error {
	// Validate role
	validRoles := []models.Role{models.RoleSuperAdmin, models.RoleAdmin, models.RoleManager, models.RoleUser, models.RoleReadOnly}
	isValidRole := false
	for _, r := range validRoles {
		if role == r {
			isValidRole = true
			break
		}
	}
	
	if !isValidRole {
		return fmt.Errorf("invalid role: %s", role)
	}
	
	// Get user to update
	user := new(models.User)
	err := s.db.Model(user).Where("id = ?", userID).Select()
	if err != nil {
		if errors.Is(err, pg.ErrNoRows) {
			return errors.New("user not found")
		}
		return fmt.Errorf("failed to get user: %w", err)
	}
	
	// Store old role for audit
	oldRole := user.Role
	
	// Update user role
	_, err = s.db.Model(user).
		Set("role = ?", role).
		Set("updated_at = ?", time.Now()).
		Where("id = ?", userID).
		Update()
	
	if err != nil {
		return fmt.Errorf("failed to update user role: %w", err)
	}
	
	// Log role change
	s.auditSvc.LogAction(ctx, user.TenantID, updaterID, models.AuditActionUpdate, 
		"user", userID.String(), fmt.Sprintf("User role changed from %s to %s", oldRole, role), 
		ipAddress, userAgent)
	
	return nil
} 