package api

import (
	"net/http"
	"strconv"
	"time"

	"gobackend/internal/auth"
	"gobackend/internal/middleware"
	"gobackend/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ResponseError represents an error response
type ResponseError struct {
	Error string `json:"error"`
}

// HealthCheckResponse represents the health check response
type HealthCheckResponse struct {
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
	Version   string `json:"version"`
}

// PaginationParams represents pagination parameters
type PaginationParams struct {
	Page     int `form:"page" binding:"min=1"`
	PageSize int `form:"page_size" binding:"min=1,max=100"`
}

// GetDefaultPagination returns default pagination parameters
func GetDefaultPagination(c *gin.Context) PaginationParams {
	var params PaginationParams

	// Set defaults
	params.Page = 1
	params.PageSize = 20

	// Parse from query string
	pageStr := c.DefaultQuery("page", "1")
	pageSizeStr := c.DefaultQuery("page_size", "20")

	// Convert to integers
	if page, err := strconv.Atoi(pageStr); err == nil && page > 0 {
		params.Page = page
	}

	if pageSize, err := strconv.Atoi(pageSizeStr); err == nil && pageSize > 0 && pageSize <= 100 {
		params.PageSize = pageSize
	}

	return params
}

// HealthCheck handles the health check endpoint
func (r *Router) HealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, HealthCheckResponse{
		Status:    "ok",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Version:   "1.0.0", // This could be loaded from a version file or build info
	})
}

// Login handles user login
func (r *Router) Login(c *gin.Context) {
	var req auth.LoginRequest
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
	resp, err := r.authService.Login(c.Request.Context(), req, ipAddress, userAgent)
	if err != nil {
		status := http.StatusInternalServerError

		// Map specific errors to appropriate status codes
		switch err {
		case auth.ErrInvalidCredentials:
			status = http.StatusUnauthorized
		case auth.ErrUserNotActive:
			status = http.StatusForbidden
		case auth.ErrUserLocked:
			status = http.StatusForbidden
		case auth.ErrMaxLoginAttempts:
			status = http.StatusTooManyRequests
		}

		c.JSON(status, ResponseError{
			Error: err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// RefreshToken handles token refresh
func (r *Router) RefreshToken(c *gin.Context) {
	type refreshRequest struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	var req refreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ResponseError{
			Error: "Invalid request: " + err.Error(),
		})
		return
	}

	// Get client info for audit
	ipAddress := middleware.ClientIP(c)
	userAgent := c.GetHeader("User-Agent")

	// Attempt to refresh token
	resp, err := r.authService.Refresh(c.Request.Context(), req.RefreshToken, ipAddress, userAgent)
	if err != nil {
		status := http.StatusInternalServerError

		if err == auth.ErrInvalidRefreshToken {
			status = http.StatusUnauthorized
		}

		c.JSON(status, ResponseError{
			Error: err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// Logout handles user logout
func (r *Router) Logout(c *gin.Context) {
	type logoutRequest struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	var req logoutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ResponseError{
			Error: "Invalid request: " + err.Error(),
		})
		return
	}

	// Validate the refresh token to get user ID
	token, err := r.authService.ValidateToken(req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, ResponseError{
			Error: "Invalid token",
		})
		return
	}

	// Parse user ID
	userID, err := uuid.Parse(token.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ResponseError{
			Error: "Invalid user ID in token",
		})
		return
	}

	// Get client info for audit
	ipAddress := middleware.ClientIP(c)
	userAgent := c.GetHeader("User-Agent")

	// Perform logout
	if err := r.authService.Logout(c.Request.Context(), userID, ipAddress, userAgent); err != nil {
		c.JSON(http.StatusInternalServerError, ResponseError{
			Error: "Logout failed: " + err.Error(),
		})
		return
	}

	c.Status(http.StatusNoContent)
}

// ListUsers handles listing users
func (r *Router) ListUsers(c *gin.Context) {
	// This is a placeholder implementation and would need to be connected to a user service
	c.JSON(http.StatusOK, gin.H{
		"message": "List users endpoint",
	})
}

// GetUser handles getting a single user
func (r *Router) GetUser(c *gin.Context) {
	// This is a placeholder implementation and would need to be connected to a user service
	c.JSON(http.StatusOK, gin.H{
		"message": "Get user endpoint",
		"id":      c.Param("id"),
	})
}

// UpdateUser handles updating a user
func (r *Router) UpdateUser(c *gin.Context) {
	// This is a placeholder implementation and would need to be connected to a user service
	c.JSON(http.StatusOK, gin.H{
		"message": "Update user endpoint",
		"id":      c.Param("id"),
	})
}

// ChangePassword handles changing a user's password
func (r *Router) ChangePassword(c *gin.Context) {
	// This is a placeholder implementation and would need to be connected to a user service
	c.JSON(http.StatusOK, gin.H{
		"message": "Change password endpoint",
		"id":      c.Param("id"),
	})
}

// ConfigureMFA handles configuring multi-factor authentication
func (r *Router) ConfigureMFA(c *gin.Context) {
	// This is a placeholder implementation and would need to be connected to a user service
	c.JSON(http.StatusOK, gin.H{
		"message": "Configure MFA endpoint",
		"id":      c.Param("id"),
	})
}

// ListTenants handles listing tenants
func (r *Router) ListTenants(c *gin.Context) {
	// This is a placeholder implementation and would need to be connected to a tenant service
	c.JSON(http.StatusOK, gin.H{
		"message": "List tenants endpoint",
	})
}

// GetTenant handles getting a single tenant
func (r *Router) GetTenant(c *gin.Context) {
	// This is a placeholder implementation and would need to be connected to a tenant service
	c.JSON(http.StatusOK, gin.H{
		"message": "Get tenant endpoint",
		"id":      c.Param("id"),
	})
}

// UpdateTenant handles updating a tenant
func (r *Router) UpdateTenant(c *gin.Context) {
	// This is a placeholder implementation and would need to be connected to a tenant service
	c.JSON(http.StatusOK, gin.H{
		"message": "Update tenant endpoint",
		"id":      c.Param("id"),
	})
}

// ListAuditLogs handles listing audit logs
func (r *Router) ListAuditLogs(c *gin.Context) {
	// This is a placeholder implementation and would need to be connected to an audit service
	c.JSON(http.StatusOK, gin.H{
		"message": "List audit logs endpoint",
	})
}

// Signup handles user registration
func (r *Router) Signup(c *gin.Context) {
	var req auth.SignupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ResponseError{
			Error: "Invalid request: " + err.Error(),
		})
		return
	}

	// Get client info for audit
	ipAddress := middleware.ClientIP(c)
	userAgent := c.GetHeader("User-Agent")

	// Attempt signup
	resp, err := r.authService.Signup(c.Request.Context(), req, ipAddress, userAgent)
	if err != nil {
		status := http.StatusInternalServerError

		// Map specific errors to appropriate status codes
		switch err {
		case auth.ErrEmailAlreadyExists:
			status = http.StatusConflict
		case auth.ErrInvalidEmail, auth.ErrInvalidPassword:
			status = http.StatusBadRequest
		case auth.ErrTenantNotFound, auth.ErrOrganizationNotFound:
			status = http.StatusNotFound
		}

		c.JSON(status, ResponseError{
			Error: err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, resp)
}

// UpdateUserRoleRequest represents the request to update a user's role
type UpdateUserRoleRequest struct {
	Role string `json:"role" binding:"required"`
}

// UpdateUserRole handles updating a user's role
func (r *Router) UpdateUserRole(c *gin.Context) {
	// Parse user ID from URL
	userIDStr := c.Param("id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, ResponseError{
			Error: "Invalid user ID",
		})
		return
	}

	// Parse request body
	var req UpdateUserRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ResponseError{
			Error: "Invalid request: " + err.Error(),
		})
		return
	}

	// Get the current user ID from context for audit
	currentUserIDStr, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, ResponseError{
			Error: "User not authenticated",
		})
		return
	}

	currentUserID, err := uuid.Parse(currentUserIDStr.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, ResponseError{
			Error: "Invalid current user ID",
		})
		return
	}

	// Get client info for audit
	ipAddress := middleware.ClientIP(c)
	userAgent := c.GetHeader("User-Agent")

	// Update the role
	err = r.authService.UpdateUserRole(
		c.Request.Context(),
		userID,
		models.Role(req.Role),
		currentUserID,
		ipAddress,
		userAgent,
	)

	if err != nil {
		status := http.StatusInternalServerError

		if err.Error() == "user not found" {
			status = http.StatusNotFound
		} else if err.Error() == "invalid role" {
			status = http.StatusBadRequest
		}

		c.JSON(status, ResponseError{
			Error: "Failed to update role: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "User role updated successfully",
	})
}
