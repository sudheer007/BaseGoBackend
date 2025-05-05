package api

import (
	"net/http"

	"gobackend/internal/auth"
	"gobackend/internal/middleware"
	"gobackend/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// GoogleAuthHandlers handles Google authentication-related API requests
type GoogleAuthHandlers struct {
	googleAuthService *auth.GoogleService
}

// NewGoogleAuthHandlers creates a new Google auth handlers instance
func NewGoogleAuthHandlers(googleAuthService *auth.GoogleService) *GoogleAuthHandlers {
	return &GoogleAuthHandlers{
		googleAuthService: googleAuthService,
	}
}

// Login handles Google authentication
// @Summary Authenticate with Google ID token
// @Description Verify Google ID token and login or create user
// @Tags auth
// @Accept json
// @Produce json
// @Param token body auth.GoogleTokenRequest true "Google ID token"
// @Success 200 {object} auth.TokenResponse
// @Failure 400 {object} ResponseError
// @Failure 401 {object} ResponseError
// @Failure 500 {object} ResponseError
// @Router /api/v1/auth/google/login [post]
func (h *GoogleAuthHandlers) Login(c *gin.Context) {
	var req auth.GoogleTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ResponseError{
			Error: "Invalid request: " + err.Error(),
		})
		return
	}

	// Get client info for audit
	ipAddress := middleware.ClientIP(c)
	userAgent := c.GetHeader("User-Agent")

	// Attempt Google login
	resp, err := h.googleAuthService.GoogleLogin(c.Request.Context(), req, ipAddress, userAgent)
	if err != nil {
		// Return specific status codes based on error type
		status := http.StatusInternalServerError
		errMsg := err.Error()

		// Map specific errors to appropriate status codes
		switch errMsg {
		case "invalid Google ID token":
			status = http.StatusUnauthorized
		case "Google authentication failed":
			status = http.StatusUnauthorized
		case "user account is not active":
			status = http.StatusForbidden
		}

		c.JSON(status, ResponseError{
			Error: errMsg,
		})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// Logout handles user logout
// @Summary Logout user
// @Description Invalidate the current user session
// @Tags auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]string
// @Failure 401 {object} ResponseError
// @Failure 500 {object} ResponseError
// @Router /api/v1/auth/google/logout [post]
func (h *GoogleAuthHandlers) Logout(c *gin.Context) {
	// Get user ID from the context (set by auth middleware)
	userIDStr, exists := c.Get(middleware.UserIDKey)
	if !exists {
		c.JSON(http.StatusUnauthorized, ResponseError{
			Error: "User not authenticated",
		})
		return
	}

	// Parse the user ID
	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, ResponseError{
			Error: "Invalid user ID",
		})
		return
	}

	// Get client info for audit
	ipAddress := middleware.ClientIP(c)
	userAgent := c.GetHeader("User-Agent")

	// Perform logout (invalidate refresh token)
	// Note: In a real implementation, you might want to invalidate the specific
	// refresh token used by this session, not all tokens
	if err := h.googleAuthService.AuthSvc.Logout(c.Request.Context(), userID, ipAddress, userAgent); err != nil {
		c.JSON(http.StatusInternalServerError, ResponseError{
			Error: "Failed to logout: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Successfully logged out",
	})
}

// GetUserInfo returns information about the current user
// @Summary Get current user information
// @Description Return information about the currently authenticated user
// @Tags auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} UserResponse
// @Failure 401 {object} ResponseError
// @Failure 500 {object} ResponseError
// @Router /api/v1/auth/google/user [get]
func (h *GoogleAuthHandlers) GetUserInfo(c *gin.Context) {
	// Get user ID from the context (set by auth middleware)
	userIDStr, exists := c.Get(middleware.UserIDKey)
	if !exists {
		c.JSON(http.StatusUnauthorized, ResponseError{
			Error: "User not authenticated",
		})
		return
	}

	// Get user details
	user, err := h.googleAuthService.GetUserFromToken(c.Request.Context(), userIDStr.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, ResponseError{
			Error: "Failed to get user information: " + err.Error(),
		})
		return
	}

	// Return user information
	c.JSON(http.StatusOK, formatUserResponse(user))
}

// UserResponse is the response format for user information
type UserResponse struct {
	ID           string `json:"id"`
	Email        string `json:"email"`
	FirstName    string `json:"first_name"`
	LastName     string `json:"last_name"`
	FullName     string `json:"full_name"`
	Role         string `json:"role"`
	TenantID     string `json:"tenant_id"`
	ProfileImage string `json:"profile_image,omitempty"`
	GoogleID     string `json:"google_id,omitempty"`
}

// formatUserResponse formats a user model into a user response
func formatUserResponse(user *models.User) UserResponse {
	return UserResponse{
		ID:           user.ID.String(),
		Email:        user.Email,
		FirstName:    user.FirstName,
		LastName:     user.LastName,
		FullName:     user.FullName(),
		Role:         string(user.Role),
		TenantID:     user.TenantID.String(),
		ProfileImage: user.ProfileImage,
		GoogleID:     user.GoogleID,
	}
}
