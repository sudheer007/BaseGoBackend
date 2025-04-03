package middleware

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gobackend/internal/auth"
	"gobackend/internal/models"
)

// AuthContext keys
const (
	UserIDKey   = "user_id"
	TenantIDKey = "tenant_id"
	EmailKey    = "email"
	RoleKey     = "role"
)

// AuthMiddleware handles authentication checking
type AuthMiddleware struct {
	authSvc *auth.Service
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(authSvc *auth.Service) *AuthMiddleware {
	return &AuthMiddleware{
		authSvc: authSvc,
	}
}

// Authenticate verifies the JWT token and injects user claims into the context
func (m *AuthMiddleware) Authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get the Authorization header
		header := c.GetHeader("Authorization")
		if header == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization header is missing",
			})
			return
		}

		// Get the token from the header
		parts := strings.Split(header, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid authorization header format",
			})
			return
		}

		tokenString := parts[1]
		claims, err := m.authSvc.ValidateToken(tokenString)
		if err != nil {
			if errors.Is(err, auth.ErrInvalidToken) {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "Invalid or expired token",
				})
				return
			}
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to validate token",
			})
			return
		}

		// Set claims in the context
		c.Set(UserIDKey, claims.UserID)
		c.Set(TenantIDKey, claims.TenantID)
		c.Set(EmailKey, claims.Email)
		c.Set(RoleKey, claims.Role)

		c.Next()
	}
}

// RequireRole ensures the user has a required role
func (m *AuthMiddleware) RequireRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get the role from context (set by Authenticate middleware)
		role, exists := c.Get(RoleKey)
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "User not authenticated",
			})
			return
		}

		userRole := role.(string)

		// Check if the user's role is in the allowed roles
		allowed := false
		for _, r := range roles {
			if userRole == r {
				allowed = true
				break
			}
		}

		if !allowed {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Insufficient permissions",
			})
			return
		}

		c.Next()
	}
}

// GetUserIDFromContext gets the user ID from the context
func GetUserIDFromContext(ctx context.Context) (uuid.UUID, error) {
	userIDStr, ok := ctx.Value(UserIDKey).(string)
	if !ok {
		return uuid.Nil, errors.New("user ID not found in context")
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return uuid.Nil, errors.New("invalid user ID format")
	}

	return userID, nil
}

// GetTenantIDFromContext gets the tenant ID from the context
func GetTenantIDFromContext(ctx context.Context) (uuid.UUID, error) {
	tenantIDStr, ok := ctx.Value(TenantIDKey).(string)
	if !ok {
		return uuid.Nil, errors.New("tenant ID not found in context")
	}

	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		return uuid.Nil, errors.New("invalid tenant ID format")
	}

	return tenantID, nil
}

// RequireTenantAccess ensures the user has access to a specific tenant
func (m *AuthMiddleware) RequireTenantAccess() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get the tenant ID from the context (set by Authenticate middleware)
		contextTenantID, exists := c.Get(TenantIDKey)
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "User not authenticated",
			})
			return
		}

		// Get the tenant ID from the URL parameter
		paramTenantID := c.Param("tenantId")
		if paramTenantID == "" {
			c.Next() // No tenant ID in URL, skip the check
			return
		}

		// Verify the user belongs to the tenant they're trying to access
		if contextTenantID != paramTenantID {
			// If the user is trying to access a different tenant
			// Check role for cross-tenant access (e.g., admin role)
			role, _ := c.Get(RoleKey)
			userRole := role.(string)
			
			// Allow cross-tenant access only for admin role
			if userRole != string(models.RoleAdmin) {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error": "Access to this tenant is not allowed",
				})
				return
			}
		}

		c.Next()
	}
} 