package middleware

import (
	"context"
	"net/http"

	"gobackend/internal/models"
	"gobackend/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// AuthorizationMiddleware handles permission checking
type AuthorizationMiddleware struct {
	authzSvc *services.AuthorizationService
}

// NewAuthorizationMiddleware creates a new authorization middleware
func NewAuthorizationMiddleware(authzSvc *services.AuthorizationService) *AuthorizationMiddleware {
	return &AuthorizationMiddleware{
		authzSvc: authzSvc,
	}
}

// RequirePermission ensures the user has a specific permission
func (m *AuthorizationMiddleware) RequirePermission(resource, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get the user ID from context (set by Authenticate middleware)
		userIDStr, exists := c.Get(UserIDKey)
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "User not authenticated",
			})
			return
		}

		userID, err := uuid.Parse(userIDStr.(string))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "Invalid user ID format",
			})
			return
		}

		// Check if the user has the required permission
		hasPermission, err := m.authzSvc.HasPermission(c.Request.Context(), userID, resource, action)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to check permissions",
			})
			return
		}

		if !hasPermission {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Permission denied",
			})
			return
		}

		c.Next()
	}
}

// RequireResourceAccess ensures the user has access to a specific resource
func (m *AuthorizationMiddleware) RequireResourceAccess(resourceType string, minAccessLevel models.AccessLevel) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get the user ID from context (set by Authenticate middleware)
		userIDStr, exists := c.Get(UserIDKey)
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "User not authenticated",
			})
			return
		}

		userID, err := uuid.Parse(userIDStr.(string))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "Invalid user ID format",
			})
			return
		}

		// Get the resource ID from the URL parameter
		resourceIDStr := c.Param("id")
		if resourceIDStr == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "Resource ID not provided",
			})
			return
		}

		resourceID, err := uuid.Parse(resourceIDStr)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "Invalid resource ID format",
			})
			return
		}

		// Check if the user has access to the resource
		hasAccess, err := m.authzSvc.HasResourceAccess(c.Request.Context(), userID, resourceID, resourceType, minAccessLevel)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to check resource access",
			})
			return
		}

		if !hasAccess {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Access denied to this resource",
			})
			return
		}

		c.Next()
	}
}

// RequireOrganizationAccess ensures the user has access to an organization
func (m *AuthorizationMiddleware) RequireOrganizationAccess(minAccessLevel models.AccessLevel) gin.HandlerFunc {
	return m.RequireResourceAccess("organization", minAccessLevel)
}

// RequireTeamAccess ensures the user has access to a team
func (m *AuthorizationMiddleware) RequireTeamAccess(minAccessLevel models.AccessLevel) gin.HandlerFunc {
	return m.RequireResourceAccess("team", minAccessLevel)
}

// RequireUserAccess ensures the user has access to another user's data
func (m *AuthorizationMiddleware) RequireUserAccess(minAccessLevel models.AccessLevel) gin.HandlerFunc {
	return m.RequireResourceAccess("user", minAccessLevel)
}

// GetAuthorizationContext creates a context with authorization information
func (m *AuthorizationMiddleware) GetAuthorizationContext(c *gin.Context) context.Context {
	ctx := c.Request.Context()

	// Add user ID to context if it exists
	if userIDStr, exists := c.Get(UserIDKey); exists {
		if userID, err := uuid.Parse(userIDStr.(string)); err == nil {
			ctx = context.WithValue(ctx, UserIDKey, userID.String())
		}
	}

	// Add role to context if it exists
	if role, exists := c.Get(RoleKey); exists {
		ctx = context.WithValue(ctx, RoleKey, role.(string))
	}

	return ctx
}
