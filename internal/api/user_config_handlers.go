package api

import (
	"net/http"

	"gobackend/internal/middleware"
	"gobackend/internal/models"
	"gobackend/internal/services"

	"github.com/gin-gonic/gin"
)

// UserConfigRequest represents the request for updating user configuration
type UserConfigRequest struct {
	UserID   string              `json:"user_id" binding:"required"`
	Settings models.UserSettings `json:"settings" binding:"required"`
}

// UserConfigHandlers handles user configuration-related API requests
type UserConfigHandlers struct {
	userConfigService *services.UserConfigService
}

// NewUserConfigHandlers creates a new user config handlers instance
func NewUserConfigHandlers(userConfigService *services.UserConfigService) *UserConfigHandlers {
	return &UserConfigHandlers{
		userConfigService: userConfigService,
	}
}

// UpdateUserConfig handles updating user configuration
// @Summary Update user configuration
// @Description Update user configuration based on the provided user_id
// @Tags users
// @Accept json
// @Produce json
// @Param config body UserConfigRequest true "User configuration"
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} ResponseError
// @Failure 401 {object} ResponseError
// @Failure 404 {object} ResponseError
// @Failure 500 {object} ResponseError
// @Router /api/v1/users/update-user-config [post]
func (h *UserConfigHandlers) UpdateUserConfig(c *gin.Context) {
	// Parse request
	var req UserConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ResponseError{
			Error: "Invalid request: " + err.Error(),
		})
		return
	}

	// Get current user ID from context (for authorization check)
	currentUserIDStr, exists := c.Get(middleware.UserIDKey)
	if !exists {
		c.JSON(http.StatusUnauthorized, ResponseError{
			Error: "User not authenticated",
		})
		return
	}

	// Authorization: Users can only update their own config unless they're an admin
	if currentUserIDStr.(string) != req.UserID {
		// Check if current user is admin
		currentUserRoleStr, exists := c.Get("user_role")
		if !exists || (currentUserRoleStr.(string) != string(models.RoleAdmin) &&
			currentUserRoleStr.(string) != string(models.RoleSuperAdmin)) {
			c.JSON(http.StatusForbidden, ResponseError{
				Error: "Not authorized to update another user's configuration",
			})
			return
		}
	}

	// Update the user configuration
	config, err := h.userConfigService.UpdateUserConfig(c.Request.Context(), req.UserID, req.Settings)
	if err != nil {
		status := http.StatusInternalServerError
		if err.Error() == "user not found" {
			status = http.StatusNotFound
		}

		c.JSON(status, ResponseError{
			Error: err.Error(),
		})
		return
	}

	// Return success response
	c.JSON(http.StatusOK, gin.H{
		"message": "User configuration updated successfully",
		"config":  config,
	})
}
