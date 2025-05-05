package api

import (
	"net/http"
	"strconv"

	"gobackend/internal/middleware"
	"gobackend/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// RecordingsHandlers handles API requests related to recordings
type RecordingsHandlers struct {
	recordingsService *services.RecordingsService
}

// NewRecordingsHandlers creates a new recordings handlers instance
func NewRecordingsHandlers(recordingsService *services.RecordingsService) *RecordingsHandlers {
	return &RecordingsHandlers{
		recordingsService: recordingsService,
	}
}

// GetUserRecordings handles retrieving recordings for a specific user
// @Summary Get user recordings
// @Description Retrieve recordings from Digital Ocean spaces based on user's meetings
// @Tags recordings
// @Accept json
// @Produce json
// @Param user_id path string true "User ID"
// @Param limit query int false "Maximum number of recordings to return"
// @Param offset query int false "Number of recordings to skip"
// @Security BearerAuth
// @Success 200 {object} services.GetUserRecordingsResponse
// @Failure 400 {object} ResponseError
// @Failure 401 {object} ResponseError
// @Failure 403 {object} ResponseError
// @Failure 500 {object} ResponseError
// @Router /api/v1/users/{user_id}/recordings [get]
func (h *RecordingsHandlers) GetUserRecordings(c *gin.Context) {
	// Parse the user ID from the URL parameter
	userIDStr := c.Param("user_id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, ResponseError{
			Error: "Invalid user ID",
		})
		return
	}

	// Parse pagination parameters
	limitStr := c.DefaultQuery("limit", "20")
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 0 {
		limit = 20
	}

	offsetStr := c.DefaultQuery("offset", "0")
	offset, err := strconv.Atoi(offsetStr)
	if err != nil || offset < 0 {
		offset = 0
	}

	// Get authenticated user ID from context (set by auth middleware)
	authUserIDStr, exists := c.Get(middleware.UserIDKey)
	if !exists {
		c.JSON(http.StatusUnauthorized, ResponseError{
			Error: "User not authenticated",
		})
		return
	}

	// Check if user is requesting their own recordings or has admin access
	authUserID, err := uuid.Parse(authUserIDStr.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, ResponseError{
			Error: "Invalid authentication state",
		})
		return
	}

	// Get user role from context
	roleInterface, exists := c.Get(middleware.RoleKey)
	isAdmin := false
	if exists && roleInterface.(string) == "admin" {
		isAdmin = true
	}

	// Only allow access to own recordings or if admin
	if userID != authUserID && !isAdmin {
		c.JSON(http.StatusForbidden, ResponseError{
			Error: "You don't have permission to access these recordings",
		})
		return
	}

	// Create service request
	req := services.GetUserRecordingsRequest{
		UserID: userID,
		Limit:  limit,
		Offset: offset,
	}

	// Get recordings from service
	resp, err := h.recordingsService.GetUserRecordings(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ResponseError{
			Error: "Failed to retrieve recordings: " + err.Error(),
		})
		return
	}

	// Return the recordings
	c.JSON(http.StatusOK, resp)
} 