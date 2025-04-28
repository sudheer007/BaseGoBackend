package api

import (
	"net/http"

	"gobackend/internal/models"
	"gobackend/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// AuthorizationHandlers handles authorization-related API endpoints
type AuthorizationHandlers struct {
	authzService *services.AuthorizationService
}

// NewAuthorizationHandlers creates a new authorization handlers instance
func NewAuthorizationHandlers(authzService *services.AuthorizationService) *AuthorizationHandlers {
	return &AuthorizationHandlers{
		authzService: authzService,
	}
}

// GetPermissions godoc
// @Summary Get all permissions
// @Description Get a list of all available permissions
// @Tags authorization
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {array} models.Permission
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 403 {object} map[string]string "Forbidden"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/permissions [get]
func (h *AuthorizationHandlers) GetPermissions(c *gin.Context) {
	permissions, err := h.authzService.GetPermissions(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get permissions: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, permissions)
}

// GetRolePermissions godoc
// @Summary Get permissions for a role
// @Description Get permissions assigned to a specific role
// @Tags authorization
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param role path string true "Role name"
// @Success 200 {array} models.Permission
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 403 {object} map[string]string "Forbidden"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/roles/{role}/permissions [get]
func (h *AuthorizationHandlers) GetRolePermissions(c *gin.Context) {
	role := c.Param("role")
	if role == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Role not provided",
		})
		return
	}

	permissions, err := h.authzService.GetRolePermissions(c.Request.Context(), role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get role permissions: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, permissions)
}

// AssignPermissionRequest represents a request to assign permission to a role
type AssignPermissionRequest struct {
	PermissionID uuid.UUID `json:"permissionId" binding:"required"`
}

// AssignPermissionToRole godoc
// @Summary Assign permission to role
// @Description Assign a permission to a specific role
// @Tags authorization
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param role path string true "Role name"
// @Param permission body AssignPermissionRequest true "Permission to assign"
// @Success 200 {object} map[string]string "Success message"
// @Failure 400 {object} map[string]string "Bad request"
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 403 {object} map[string]string "Forbidden"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/roles/{role}/permissions [post]
func (h *AuthorizationHandlers) AssignPermissionToRole(c *gin.Context) {
	role := c.Param("role")
	if role == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Role not provided",
		})
		return
	}

	var request AssignPermissionRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request: " + err.Error(),
		})
		return
	}

	err := h.authzService.AssignPermissionToRole(c.Request.Context(), role, request.PermissionID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to assign permission: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Permission assigned successfully",
	})
}

// RemovePermissionFromRole godoc
// @Summary Remove permission from role
// @Description Remove a permission from a specific role
// @Tags authorization
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param role path string true "Role name"
// @Param permissionId path string true "Permission ID"
// @Success 200 {object} map[string]string "Success message"
// @Failure 400 {object} map[string]string "Bad request"
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 403 {object} map[string]string "Forbidden"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/roles/{role}/permissions/{permissionId} [delete]
func (h *AuthorizationHandlers) RemovePermissionFromRole(c *gin.Context) {
	role := c.Param("role")
	if role == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Role not provided",
		})
		return
	}

	permissionIDStr := c.Param("permissionId")
	permissionID, err := uuid.Parse(permissionIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid permission ID",
		})
		return
	}

	err = h.authzService.RemovePermissionFromRole(c.Request.Context(), role, permissionID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to remove permission: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Permission removed successfully",
	})
}

// ResourceScopeRequest represents a request to create or update a resource scope
type ResourceScopeRequest struct {
	UserID       uuid.UUID          `json:"userId" binding:"required"`
	ResourceType string             `json:"resourceType" binding:"required"`
	ResourceID   uuid.UUID          `json:"resourceId" binding:"required"`
	AccessLevel  models.AccessLevel `json:"accessLevel" binding:"required"`
}

// CreateResourceScope godoc
// @Summary Create resource scope
// @Description Create a new resource scope (user-resource permission)
// @Tags authorization
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param scope body ResourceScopeRequest true "Resource scope to create"
// @Success 201 {object} models.ResourceScope
// @Failure 400 {object} map[string]string "Bad request"
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 403 {object} map[string]string "Forbidden"
// @Failure 409 {object} map[string]string "Resource scope already exists"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/resource-scopes [post]
func (h *AuthorizationHandlers) CreateResourceScope(c *gin.Context) {
	var request ResourceScopeRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request: " + err.Error(),
		})
		return
	}

	// Create the resource scope
	scope := &models.ResourceScope{
		UserID:       request.UserID,
		ResourceType: request.ResourceType,
		ResourceID:   request.ResourceID,
		AccessLevel:  request.AccessLevel,
	}

	err := h.authzService.CreateResourceScope(c.Request.Context(), scope)
	if err != nil {
		if err == services.ErrResourceScopeExists {
			c.JSON(http.StatusConflict, gin.H{
				"error": "Resource scope already exists",
			})
			return
		}
		if err == services.ErrInvalidResource {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid resource type",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create resource scope: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, scope)
}

// UpdateResourceScope godoc
// @Summary Update resource scope
// @Description Update an existing resource scope
// @Tags authorization
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Resource scope ID"
// @Param scope body ResourceScopeRequest true "Updated resource scope"
// @Success 200 {object} models.ResourceScope
// @Failure 400 {object} map[string]string "Bad request"
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 403 {object} map[string]string "Forbidden"
// @Failure 404 {object} map[string]string "Resource scope not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/resource-scopes/{id} [put]
func (h *AuthorizationHandlers) UpdateResourceScope(c *gin.Context) {
	scopeIDStr := c.Param("id")
	scopeID, err := uuid.Parse(scopeIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid resource scope ID",
		})
		return
	}

	var request ResourceScopeRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request: " + err.Error(),
		})
		return
	}

	// Update the resource scope
	scope := &models.ResourceScope{
		ID:           scopeID,
		UserID:       request.UserID,
		ResourceType: request.ResourceType,
		ResourceID:   request.ResourceID,
		AccessLevel:  request.AccessLevel,
	}

	err = h.authzService.UpdateResourceScope(c.Request.Context(), scope)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to update resource scope: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, scope)
}

// DeleteResourceScope godoc
// @Summary Delete resource scope
// @Description Delete a resource scope
// @Tags authorization
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Resource scope ID"
// @Success 200 {object} map[string]string "Success message"
// @Failure 400 {object} map[string]string "Bad request"
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 403 {object} map[string]string "Forbidden"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/resource-scopes/{id} [delete]
func (h *AuthorizationHandlers) DeleteResourceScope(c *gin.Context) {
	scopeIDStr := c.Param("id")
	scopeID, err := uuid.Parse(scopeIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid resource scope ID",
		})
		return
	}

	err = h.authzService.DeleteResourceScope(c.Request.Context(), scopeID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to delete resource scope: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Resource scope deleted successfully",
	})
}
