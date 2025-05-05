package api

import (
	"net/http"

	"gobackend/internal/data"
	"gobackend/internal/middleware"
	"gobackend/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// UserHandlers handles user-related API requests
type UserHandlers struct {
	userService *services.UserService
}

// NewUserHandlers creates a new user handlers instance
func NewUserHandlers(userService *services.UserService) *UserHandlers {
	return &UserHandlers{
		userService: userService,
	}
}

// AddUser handles the creation of a new user
// @Summary Create a new user
// @Description Create a new user in the database
// @Tags users
// @Accept json
// @Produce json
// @Param user body services.AddUserRequest true "User information"
// @Success 201 {object} services.AddUserResponse
// @Failure 400 {object} ResponseError
// @Failure 409 {object} ResponseError
// @Failure 500 {object} ResponseError
// @Router /api/v1/users [post]
func (h *UserHandlers) AddUser(c *gin.Context) {
	var req services.AddUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ResponseError{
			Error: "Invalid request: " + err.Error(),
		})
		return
	}

	// Set default values for tenant and organization IDs
	var tenantID, orgID, creatorID uuid.UUID
	
	// Try to get IDs from authenticated context if available
	tenantIDStr, tenantExists := c.Get("tenant_id")
	if tenantExists {
		if id, err := uuid.Parse(tenantIDStr.(string)); err == nil {
			tenantID = id
		}
	}
	
	orgIDStr, orgExists := c.Get("organization_id")
	if orgExists {
		if id, err := uuid.Parse(orgIDStr.(string)); err == nil {
			orgID = id
		}
	}
	
	userIDStr, userExists := c.Get("user_id")
	if userExists {
		if id, err := uuid.Parse(userIDStr.(string)); err == nil {
			creatorID = id
		}
	}
	
	// Use default tenant/org for unauthenticated requests
	if tenantID == uuid.Nil {
		// In a real implementation, you would look up the default tenant
		tenantID = uuid.New() // This would normally come from a database query
	}
	
	if orgID == uuid.Nil {
		// In a real implementation, you would look up the default organization
		orgID = uuid.New() // This would normally come from a database query
	}

	// Get client info for audit
	ipAddress := middleware.ClientIP(c)
	userAgent := c.GetHeader("User-Agent")

	// Create the user
	resp, err := h.userService.AddUser(c.Request.Context(), req, tenantID, orgID, creatorID, ipAddress, userAgent)
	if err != nil {
		status := http.StatusInternalServerError

		// Map specific errors to appropriate status codes
		if err.Error() == "email is required" || err.Error() == "password is required" {
			status = http.StatusBadRequest
		} else if err == data.ErrEmailAlreadyExists {
			status = http.StatusConflict
		}

		c.JSON(status, ResponseError{
			Error: err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, resp)
}

// GetUser handles retrieving a single user
func (h *UserHandlers) GetUser(c *gin.Context) {
	userIDStr := c.Param("id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, ResponseError{
			Error: "Invalid user ID",
		})
		return
	}

	user, err := h.userService.GetUserByID(c.Request.Context(), userID)
	if err != nil {
		status := http.StatusInternalServerError
		if err == data.ErrUserNotFound {
			status = http.StatusNotFound
		}

		c.JSON(status, ResponseError{
			Error: err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, user)
}

// ListUsers handles retrieving a list of users
func (h *UserHandlers) ListUsers(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "List users endpoint",
	})
}
