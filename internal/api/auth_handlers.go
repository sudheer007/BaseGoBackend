package api

import (
	"net/http"

	"gobackend/internal/middleware"
	"gobackend/internal/services"

	"github.com/gin-gonic/gin"
)

// AuthHandlers handles authentication-related API requests
type AuthHandlers struct {
	authService *services.AuthService
}

// NewAuthHandlers creates a new auth handlers instance
func NewAuthHandlers(authService *services.AuthService) *AuthHandlers {
	return &AuthHandlers{
		authService: authService,
	}
}

// Login handles user authentication
// @Summary Authenticate a user
// @Description Authenticate a user by checking their email and password
// @Tags auth
// @Accept json
// @Produce json
// @Param user body services.LoginRequest true "User login information"
// @Success 200 {object} services.LoginResponse
// @Failure 400 {object} ResponseError
// @Failure 401 {object} ResponseError
// @Failure 403 {object} ResponseError
// @Failure 429 {object} ResponseError
// @Failure 500 {object} ResponseError
// @Router /api/v1/auth/login [post]
func (h *AuthHandlers) Login(c *gin.Context) {
	var req services.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ResponseError{
			Error: "Invalid request: " + err.Error(),
		})
		return
	}

	// Get client info for audit
	ipAddress := middleware.ClientIP(c)
	userAgent := c.GetHeader("User-Agent")

	// Attempt login
	resp, err := h.authService.Login(c.Request.Context(), req, ipAddress, userAgent)
	if err != nil {
		// Return specific status codes based on error type
		status := http.StatusInternalServerError

		// The structured response is already created in the service
		// Here we just need to set the appropriate HTTP status
		switch err.Error() {
		case "invalid email or password":
			status = http.StatusUnauthorized
		case "user account is not active":
			status = http.StatusForbidden
		case "user account is locked":
			status = http.StatusForbidden
		case "maximum login attempts exceeded":
			status = http.StatusTooManyRequests
		}

		c.JSON(status, resp)
		return
	}

	c.JSON(http.StatusOK, resp)
} 