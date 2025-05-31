package api

import (
	"net/http"

	"gobackend/internal/middleware"
	"gobackend/internal/services"

	"github.com/gin-gonic/gin"
)

// MeetingsHandlers handles API requests related to meetings
type MeetingsHandlers struct {
	meetingsService services.MeetingsServiceInterface
}

// NewMeetingsHandlers creates a new meetings handlers instance
func NewMeetingsHandlers(meetingsService services.MeetingsServiceInterface) *MeetingsHandlers {
	return &MeetingsHandlers{
		meetingsService: meetingsService,
	}
}

// SetupMeeting handles setting up a new meeting
// @Summary Set up a meeting
// @Description Set up a meeting with customer information, time, and topic
// @Tags meetings
// @Accept json
// @Produce json
// @Param meeting body services.MeetingSetupRequest true "Meeting information"
// @Security BearerAuth
// @Success 200 {object} services.MeetingSetupResponse
// @Failure 400 {object} ResponseError
// @Failure 401 {object} ResponseError
// @Failure 500 {object} ResponseError
// @Router /api/v1/meetings/setup [post]
func (h *MeetingsHandlers) SetupMeeting(c *gin.Context) {
	// Parse the request body
	var req services.MeetingSetupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ResponseError{
			Error: "Invalid request format: " + err.Error(),
		})
		return
	}

	// Ensure the user is authenticated
	_, exists := c.Get(middleware.UserIDKey)
	if !exists {
		c.JSON(http.StatusUnauthorized, ResponseError{
			Error: "User not authenticated",
		})
		return
	}

	// Set up the meeting
	resp, err := h.meetingsService.SetupMeeting(c.Request.Context(), req)
	if err != nil {
		// Determine error type
		status := http.StatusInternalServerError
		errMsg := err.Error()

		// Map specific errors to appropriate status codes
		if errMsg == "user_id is required" ||
			errMsg == "customer is required" ||
			errMsg == "customer_mail is required" ||
			errMsg == "start_time is required" ||
			errMsg == "time_zone is required" ||
			errMsg == "topic is required" ||
			errMsg == "duration must be greater than 0" ||
			errMsg == "start_time must be in the future" {
			status = http.StatusBadRequest
		}

		c.JSON(status, ResponseError{
			Error: errMsg,
		})
		return
	}

	// Return successful response
	c.JSON(http.StatusOK, resp)
}

// GetUserMeetings handles retrieving a user's meetings
// @Summary Get user meetings
// @Description Retrieve meetings for a specific user
// @Tags meetings
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Security BearerAuth
// @Success 200 {array} services.MeetingInfo
// @Failure 400 {object} ResponseError
// @Failure 401 {object} ResponseError
// @Failure 500 {object} ResponseError
// @Router /api/v1/users/{id}/meetings [get]
func (h *MeetingsHandlers) GetUserMeetings(c *gin.Context) {
	// Get the user ID from the URL parameter
	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, ResponseError{
			Error: "User ID is required",
		})
		return
	}

	// Ensure the user is authenticated
	_, exists := c.Get(middleware.UserIDKey)
	if !exists {
		c.JSON(http.StatusUnauthorized, ResponseError{
			Error: "User not authenticated",
		})
		return
	}

	// Get user meetings
	meetings, err := h.meetingsService.GetMeetingsByUserID(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ResponseError{
			Error: "Failed to retrieve meetings: " + err.Error(),
		})
		return
	}

	// Return the meetings
	c.JSON(http.StatusOK, gin.H{
		"meetings": meetings,
		"total":    len(meetings),
	})
}

// UpcomingMeetings handles retrieving a user's upcoming meetings
// @Summary Get upcoming meetings
// @Description Retrieve upcoming meetings for a specific user
// @Tags meetings
// @Accept json
// @Produce json
// @Param details body services.UpcomingMeetingsRequest true "User details with ID and timezone"
// @Security BearerAuth
// @Success 200 {object} services.UpcomingMeetingsResponse
// @Failure 400 {object} ResponseError
// @Failure 401 {object} ResponseError
// @Failure 500 {object} ResponseError
// @Router /api/v1/meetings/upcoming-meetings [post]
func (h *MeetingsHandlers) UpcomingMeetings(c *gin.Context) {
	// Parse the request body
	var req services.UpcomingMeetingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ResponseError{
			Error: "Invalid request format: " + err.Error(),
		})
		return
	}

	// Ensure the user is authenticated
	_, exists := c.Get(middleware.UserIDKey)
	if !exists {
		c.JSON(http.StatusUnauthorized, ResponseError{
			Error: "User not authenticated",
		})
		return
	}

	// Get upcoming meetings
	resp, err := h.meetingsService.GetUpcomingMeetings(c.Request.Context(), req)
	if err != nil {
		// Determine error type
		status := http.StatusInternalServerError
		errMsg := err.Error()

		// Map specific errors to appropriate status codes
		if errMsg == "user_id is required" || errMsg == "time_zone is required" ||
			errMsg == "invalid time_zone" {
			status = http.StatusBadRequest
		}

		c.JSON(status, ResponseError{
			Error: errMsg,
		})
		return
	}

	// Return successful response
	c.JSON(http.StatusOK, resp)
}

// AddCustomScript handles adding or updating a custom script for a specific user
// @Summary Add or update custom script
// @Description Add a new custom script or update an existing one for a specific user
// @Tags meetings
// @Accept json
// @Produce json
// @Param custom_script body services.MeetingNoteRequest true "Custom script details"
// @Security BearerAuth
// @Success 200 {object} services.MeetingNoteResponse
// @Failure 400 {object} ResponseError
// @Failure 401 {object} ResponseError
// @Failure 500 {object} ResponseError
// @Router /api/v1/meetings/add-custom-script [post]
func (h *MeetingsHandlers) AddCustomScript(c *gin.Context) {
	// Parse the request body
	var req services.MeetingNoteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ResponseError{
			Error: "Invalid request format: " + err.Error(),
		})
		return
	}

	// Ensure the user is authenticated
	_, exists := c.Get(middleware.UserIDKey)
	if !exists {
		c.JSON(http.StatusUnauthorized, ResponseError{
			Error: "User not authenticated",
		})
		return
	}

	// Add or update the custom script
	resp, err := h.meetingsService.AddCustomScript(c.Request.Context(), req)
	if err != nil {
		// Determine error type
		status := http.StatusInternalServerError
		errMsg := err.Error()

		// Map specific errors to appropriate status codes
		if errMsg == "user_id is required" ||
			errMsg == "customer is required" ||
			errMsg == "topic is required" ||
			errMsg == "script is required" {
			status = http.StatusBadRequest
		}

		c.JSON(status, ResponseError{
			Error: errMsg,
		})
		return
	}

	// Return successful response
	c.JSON(http.StatusOK, resp)
}

// DisplayTopics handles retrieving topics and associated customers for a specific user
// @Summary Get topics and customers
// @Description Retrieve topics and associated customers for a specific user
// @Tags meetings
// @Accept json
// @Produce json
// @Param request body services.UserRequest true "User ID details"
// @Security BearerAuth
// @Success 200 {object} services.TopicsResponse
// @Failure 400 {object} ResponseError
// @Failure 401 {object} ResponseError
// @Failure 500 {object} ResponseError
// @Router /api/v1/meetings/display-topics [post]
func (h *MeetingsHandlers) DisplayTopics(c *gin.Context) {
	// Parse the request body
	var req services.UserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ResponseError{
			Error: "Invalid request format: " + err.Error(),
		})
		return
	}

	// Ensure the user is authenticated
	_, exists := c.Get(middleware.UserIDKey)
	if !exists {
		c.JSON(http.StatusUnauthorized, ResponseError{
			Error: "User not authenticated",
		})
		return
	}

	// Get topics and associated customers
	resp, err := h.meetingsService.GetTopics(c.Request.Context(), req)
	if err != nil {
		// Determine error type
		status := http.StatusInternalServerError
		errMsg := err.Error()

		// Map specific errors to appropriate status codes
		if errMsg == "user_id is required" {
			status = http.StatusBadRequest
		}

		c.JSON(status, ResponseError{
			Error: errMsg,
		})
		return
	}

	// Return successful response
	c.JSON(http.StatusOK, resp)
}

// GetCustomScript handles retrieving a custom script by its ID
// @Summary Get custom script
// @Description Retrieve a custom script by its ID
// @Tags meetings
// @Accept json
// @Produce json
// @Param script_id body services.ScriptId true "Script ID details"
// @Security BearerAuth
// @Success 200 {object} services.GetScriptResponse
// @Failure 400 {object} ResponseError
// @Failure 401 {object} ResponseError
// @Failure 404 {object} ResponseError
// @Failure 500 {object} ResponseError
// @Router /api/v1/meetings/get-custom-script [post]
func (h *MeetingsHandlers) GetCustomScript(c *gin.Context) {
	// Parse the request body
	var req services.ScriptId
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ResponseError{
			Error: "Invalid request format: " + err.Error(),
		})
		return
	}

	// Ensure the user is authenticated
	_, exists := c.Get(middleware.UserIDKey)
	if !exists {
		c.JSON(http.StatusUnauthorized, ResponseError{
			Error: "User not authenticated",
		})
		return
	}

	// Get the custom script
	resp, err := h.meetingsService.GetCustomScript(c.Request.Context(), req)
	if err != nil {
		// Determine error type
		status := http.StatusInternalServerError
		errMsg := err.Error()

		// Map specific errors to appropriate status codes
		if errMsg == "script_id is required" {
			status = http.StatusBadRequest
		} else if errMsg == "script not found" {
			status = http.StatusNotFound
		}

		c.JSON(status, ResponseError{
			Error: errMsg,
		})
		return
	}

	// Return successful response
	c.JSON(http.StatusOK, resp)
}

// DeleteCustomScripts handles deleting custom scripts
// @Summary Delete custom scripts
// @Description Delete custom scripts by their IDs
// @Tags meetings
// @Accept json
// @Produce json
// @Param script_ids body services.DeleteScriptId true "List of script IDs to delete"
// @Security BearerAuth
// @Success 200 {object} services.DeleteScriptResponse
// @Failure 400 {object} ResponseError
// @Failure 401 {object} ResponseError
// @Failure 500 {object} ResponseError
// @Router /api/v1/meetings/delete-custom-scripts [post]
func (h *MeetingsHandlers) DeleteCustomScripts(c *gin.Context) {
	// Parse the request body
	var req services.DeleteScriptId
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ResponseError{
			Error: "Invalid request format: " + err.Error(),
		})
		return
	}

	// Ensure the user is authenticated
	_, exists := c.Get(middleware.UserIDKey)
	if !exists {
		c.JSON(http.StatusUnauthorized, ResponseError{
			Error: "User not authenticated",
		})
		return
	}

	// Delete the custom scripts
	resp, err := h.meetingsService.DeleteCustomScripts(c.Request.Context(), req)
	if err != nil {
		// Determine error type
		status := http.StatusInternalServerError
		errMsg := err.Error()

		// Map specific errors to appropriate status codes
		if errMsg == "script_ids cannot be empty" {
			status = http.StatusBadRequest
		}

		c.JSON(status, ResponseError{
			Error: errMsg,
		})
		return
	}

	// Return successful response
	c.JSON(http.StatusOK, resp)
}
