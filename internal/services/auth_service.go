package services

import (
	"context"
	"errors"

	"gobackend/internal/auth"
	"gobackend/internal/models"

	"github.com/google/uuid"
)

// AuthService provides authentication functionality
type AuthService struct {
	authService *auth.Service
}

// NewAuthService creates a new authentication service
func NewAuthService(authService *auth.Service) *AuthService {
	return &AuthService{
		authService: authService,
	}
}

// LoginRequest represents the request to login a user
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// LoginResponse represents the response after a login attempt
type LoginResponse struct {
	Success      bool   `json:"success"`
	Message      string `json:"message"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresAt    int64  `json:"expires_at,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	UserID       string `json:"user_id,omitempty"`
	TenantID     string `json:"tenant_id,omitempty"`
	RequiresMFA  bool   `json:"requires_mfa,omitempty"`
}

// Login authenticates a user and returns authentication tokens
func (s *AuthService) Login(ctx context.Context, req LoginRequest, ipAddress, userAgent string) (*LoginResponse, error) {
	// Convert to internal auth request
	authReq := auth.LoginRequest{
		Email:    req.Email,
		Password: req.Password,
	}

	// Attempt login through the internal auth service
	resp, err := s.authService.Login(ctx, authReq, ipAddress, userAgent)
	if err != nil {
		// Return a structured error response
		return &LoginResponse{
			Success: false,
			Message: err.Error(),
		}, err
	}

	// Return a successful response with JWT tokens
	return &LoginResponse{
		Success:      true,
		Message:      "Login successful",
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		ExpiresAt:    resp.ExpiresAt,
		TokenType:    resp.TokenType,
		UserID:       resp.UserID,
		TenantID:     resp.TenantID,
		RequiresMFA:  resp.RequiresMFA,
	}, nil
}

// ValidateTokenAndGetUser validates an access token and returns the associated user
func (s *AuthService) ValidateTokenAndGetUser(ctx context.Context, token string) (*models.User, error) {
	// Validate the token
	claims, err := s.authService.ValidateToken(token)
	if err != nil {
		return nil, errors.New("invalid token")
	}

	// Extract the user ID from the claims
	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		return nil, errors.New("invalid user ID in token")
	}

	// This would normally fetch the user from the database
	// For now, we'll just return a minimal user object
	user := &models.User{
		ID:    userID,
		Email: claims.Email,
		Role:  models.Role(claims.Role),
	}

	return user, nil
}
