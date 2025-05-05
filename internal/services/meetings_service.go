package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// MeetingSetup defines the request structure for setting up a meeting
type MeetingSetup struct {
	UserID       string `json:"user_id" binding:"required"`
	Customer     string `json:"customer" binding:"required"`
	CustomerMail string `json:"customer_mail" binding:"required,email"`
	StartTime    string `json:"start_time" binding:"required"` // Format: "2025-02-24 06:00"
	TimeZone     string `json:"time_zone" binding:"required"`
	Topic        string `json:"topic" binding:"required"`
	Duration     int    `json:"duration" binding:"required"` // Duration in seconds
}

// MeetingSetupRequest wraps the meeting setup information
type MeetingSetupRequest struct {
	Meeting MeetingSetup `json:"meeting" binding:"required"`
}

// MeetingSetupResponse defines the response structure for the setup meeting endpoint
type MeetingSetupResponse struct {
	Success      bool   `json:"success"`
	Message      string `json:"message"`
	MeetingID    string `json:"meeting_id,omitempty"`
	JoinURL      string `json:"join_url,omitempty"`
	RecordingURL string `json:"recording_url,omitempty"`
}

// MeetingInfo represents a meeting in the system
type MeetingInfo struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	Customer     string    `json:"customer"`
	CustomerMail string    `json:"customer_mail"`
	StartTime    time.Time `json:"start_time"`
	TimeZone     string    `json:"time_zone"`
	Topic        string    `json:"topic"`
	Duration     int       `json:"duration"`
	JoinURL      string    `json:"join_url"`
	Status       string    `json:"status"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// UserDetails defines the request structure for retrieving upcoming meetings
type UserDetails struct {
	UserID   string `json:"user_id" binding:"required"`
	TimeZone string `json:"time_zone" binding:"required"`
}

// UpcomingMeetingsRequest wraps the user details
type UpcomingMeetingsRequest struct {
	Details UserDetails `json:"details" binding:"required"`
}

// UpcomingMeetingsResponse defines the response structure for the upcoming meetings endpoint
type UpcomingMeetingsResponse struct {
	Meetings []MeetingInfo `json:"meetings"`
	Total    int           `json:"total"`
}

// MeetingsServiceInterface defines the interface for meeting services
type MeetingsServiceInterface interface {
	SetupMeeting(ctx context.Context, req MeetingSetupRequest) (*MeetingSetupResponse, error)
	GetMeetingsByUserID(ctx context.Context, userID string) ([]MeetingInfo, error)
	GetUpcomingMeetings(ctx context.Context, req UpcomingMeetingsRequest) (*UpcomingMeetingsResponse, error)
	AddCustomScript(ctx context.Context, req MeetingNoteRequest) (*MeetingNoteResponse, error)
	GetTopics(ctx context.Context, req UserRequest) (*TopicsResponse, error)
	GetCustomScript(ctx context.Context, req ScriptId) (*GetScriptResponse, error)
	DeleteCustomScripts(ctx context.Context, req DeleteScriptId) (*DeleteScriptResponse, error)
}

// MeetingsService provides functionality related to meetings
type MeetingsService struct {
	// Dependencies would go here:
	// - Database repository to store meeting data
	// - Integration with meeting provider (Zoom, Teams, etc)
	// - Any other dependencies
}

// NewMeetingsService creates a new meetings service
func NewMeetingsService() *MeetingsService {
	return &MeetingsService{
		// Initialize dependencies
	}
}

// SetupMeeting creates a new meeting
func (s *MeetingsService) SetupMeeting(ctx context.Context, req MeetingSetupRequest) (*MeetingSetupResponse, error) {
	meeting := req.Meeting

	// Validate input
	if meeting.UserID == "" {
		return nil, errors.New("user_id is required")
	}
	if meeting.Customer == "" {
		return nil, errors.New("customer is required")
	}
	if meeting.CustomerMail == "" {
		return nil, errors.New("customer_mail is required")
	}
	if meeting.StartTime == "" {
		return nil, errors.New("start_time is required")
	}
	if meeting.TimeZone == "" {
		return nil, errors.New("time_zone is required")
	}
	if meeting.Topic == "" {
		return nil, errors.New("topic is required")
	}
	if meeting.Duration <= 0 {
		return nil, errors.New("duration must be greater than 0")
	}

	// Parse the start time
	startTime, err := time.Parse("2006-01-02 15:04", meeting.StartTime)
	if err != nil {
		return nil, fmt.Errorf("invalid start_time format: %w", err)
	}

	// Check that start time is in the future
	if startTime.Before(time.Now()) {
		return nil, errors.New("start_time must be in the future")
	}

	// TODO: In a real implementation, we would:
	// 1. Create a meeting in the database
	// 2. If using an external meeting provider, set up the meeting there
	// 3. Return the meeting details to the client

	// Mock implementation
	meetingID := uuid.New().String()
	joinURL := fmt.Sprintf("https://meetings.example.com/join/%s", meetingID)

	// Create response
	response := &MeetingSetupResponse{
		Success:   true,
		Message:   "Meeting scheduled successfully",
		MeetingID: meetingID,
		JoinURL:   joinURL,
	}

	return response, nil
}

// GetMeetingsByUserID retrieves all meetings for a specific user
func (s *MeetingsService) GetMeetingsByUserID(ctx context.Context, userID string) ([]MeetingInfo, error) {
	if userID == "" {
		return nil, errors.New("user_id is required")
	}

	// TODO: In a real implementation, we would:
	// 1. Query the database to find meetings associated with the user
	// 2. Return the meetings to the client

	// Mock implementation
	mockMeetings := []MeetingInfo{
		{
			ID:           uuid.New().String(),
			UserID:       userID,
			Customer:     "Sample Customer",
			CustomerMail: "customer@example.com",
			StartTime:    time.Now().Add(24 * time.Hour),
			TimeZone:     "UTC",
			Topic:        "Project Kickoff",
			Duration:     3600,
			JoinURL:      fmt.Sprintf("https://meetings.example.com/join/%s", uuid.New().String()),
			Status:       "scheduled",
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		},
	}

	return mockMeetings, nil
}

// GetUpcomingMeetings retrieves upcoming meetings for a specific user
func (s *MeetingsService) GetUpcomingMeetings(ctx context.Context, req UpcomingMeetingsRequest) (*UpcomingMeetingsResponse, error) {
	details := req.Details

	// Validate input
	if details.UserID == "" {
		return nil, errors.New("user_id is required")
	}
	if details.TimeZone == "" {
		return nil, errors.New("time_zone is required")
	}

	// Validate the timezone
	_, err := time.LoadLocation(details.TimeZone)
	if err != nil {
		return nil, fmt.Errorf("invalid time_zone: %w", err)
	}

	// TODO: In a real implementation, we would:
	// 1. Query the database to find upcoming meetings associated with the user
	// 2. Filter by meetings where start_time > current time
	// 3. Convert meeting times to the user's time zone
	// 4. Return the meetings to the client

	// Current time in UTC
	now := time.Now().UTC()

	// Mock implementation
	mockMeetings := []MeetingInfo{
		{
			ID:           uuid.New().String(),
			UserID:       details.UserID,
			Customer:     "ABC Corp",
			CustomerMail: "contact@abccorp.com",
			StartTime:    now.Add(24 * time.Hour),
			TimeZone:     details.TimeZone,
			Topic:        "Product Demo",
			Duration:     3600,
			JoinURL:      fmt.Sprintf("https://meetings.example.com/join/%s", uuid.New().String()),
			Status:       "scheduled",
			CreatedAt:    now,
			UpdatedAt:    now,
		},
		{
			ID:           uuid.New().String(),
			UserID:       details.UserID,
			Customer:     "XYZ Ltd",
			CustomerMail: "info@xyzltd.com",
			StartTime:    now.Add(48 * time.Hour),
			TimeZone:     details.TimeZone,
			Topic:        "Quarterly Review",
			Duration:     7200,
			JoinURL:      fmt.Sprintf("https://meetings.example.com/join/%s", uuid.New().String()),
			Status:       "scheduled",
			CreatedAt:    now,
			UpdatedAt:    now,
		},
	}

	// Prepare response
	response := &UpcomingMeetingsResponse{
		Meetings: mockMeetings,
		Total:    len(mockMeetings),
	}

	return response, nil
}

// MeetingNoteRequest defines the request structure for adding a custom script
type MeetingNoteRequest struct {
	CustomScript MeetingNote `json:"custom_script" binding:"required"`
}

// MeetingNote contains details about a meeting script
type MeetingNote struct {
	UserID   string `json:"user_id" binding:"required"`
	Customer string `json:"customer" binding:"required"`
	Topic    string `json:"topic" binding:"required"`
	Script   string `json:"script" binding:"required"`
	ScriptID string `json:"script_id"` // Optional for adding new scripts
}

// MeetingNoteResponse defines the response structure for the add/update script endpoint
type MeetingNoteResponse struct {
	Success  bool   `json:"success"`
	Message  string `json:"message"`
	ScriptID string `json:"script_id,omitempty"`
}

// AddCustomScript adds or updates a custom script for a specific user
func (s *MeetingsService) AddCustomScript(ctx context.Context, req MeetingNoteRequest) (*MeetingNoteResponse, error) {
	script := req.CustomScript

	// Validate input
	if script.UserID == "" {
		return nil, errors.New("user_id is required")
	}
	if script.Customer == "" {
		return nil, errors.New("customer is required")
	}
	if script.Topic == "" {
		return nil, errors.New("topic is required")
	}
	if script.Script == "" {
		return nil, errors.New("script is required")
	}

	// TODO: In a real implementation, we would:
	// 1. Check if script_id exists, if so update the existing script
	// 2. If script_id is empty, create a new script and generate an ID
	// 3. Store in database
	// 4. Return the response with the script ID

	var message string
	var scriptID string

	if script.ScriptID == "" {
		// Create a new script
		scriptID = uuid.New().String()
		message = "Custom script added successfully"
	} else {
		// Update existing script
		scriptID = script.ScriptID
		message = "Custom script updated successfully"
	}

	// Create response
	response := &MeetingNoteResponse{
		Success:  true,
		Message:  message,
		ScriptID: scriptID,
	}

	return response, nil
}

// UserRequest defines the request structure for user-specific endpoints
type UserRequest struct {
	UserID string `json:"user_id" binding:"required"`
}

// TopicsResponse defines the response structure for the display-topics endpoint
type TopicsResponse struct {
	Topics map[string][]string `json:"topics"` // Map of topic -> list of customers/subtopics
}

// GetTopics retrieves topics and associated customers for a specific user
func (s *MeetingsService) GetTopics(ctx context.Context, req UserRequest) (*TopicsResponse, error) {
	// Validate input
	if req.UserID == "" {
		return nil, errors.New("user_id is required")
	}

	// TODO: In a real implementation, we would:
	// 1. Query the database to find all meetings/scripts for the user
	// 2. Extract unique topics and their associated customers
	// 3. Return the mapping of topics to customers

	// Mock implementation - simulate fetching topics and customers from a database
	topicsMap := map[string][]string{
		"Product Demo": {
			"ABC Corp",
			"XYZ Ltd",
			"Tech Solutions",
		},
		"Discovery Call": {
			"AMD",
			"Intel",
			"Nvidia",
		},
		"Quarterly Review": {
			"Microsoft",
			"Apple",
			"Google",
		},
		"Project Kickoff": {
			"Startup Inc",
			"Enterprise Co",
		},
	}

	// Create response
	response := &TopicsResponse{
		Topics: topicsMap,
	}

	return response, nil
}

// ScriptId defines the request structure for retrieving a custom script
type ScriptId struct {
	ScriptID string `json:"script_id" binding:"required"`
}

// DeleteScriptId defines the request structure for deleting custom scripts
type DeleteScriptId struct {
	ScriptIDs []string `json:"script_ids" binding:"required"`
}

// GetScriptResponse defines the response structure for the get-custom-script endpoint
type GetScriptResponse struct {
	ScriptID string `json:"script_id"`
	UserID   string `json:"user_id"`
	Customer string `json:"customer"`
	Topic    string `json:"topic"`
	Script   string `json:"script"`
}

// DeleteScriptResponse defines the response structure for the delete-custom-scripts endpoint
type DeleteScriptResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Count   int    `json:"count"` // Number of scripts deleted
}

// GetCustomScript retrieves a custom script by its ID
func (s *MeetingsService) GetCustomScript(ctx context.Context, req ScriptId) (*GetScriptResponse, error) {
	// Validate input
	if req.ScriptID == "" {
		return nil, errors.New("script_id is required")
	}

	// TODO: In a real implementation, we would:
	// 1. Query the database to find the script with the given ID
	// 2. Return the script details to the client
	// 3. Handle errors like script not found

	// Mock implementation - simulate fetching a script from a database
	// In a real implementation, we would check if the script exists
	if req.ScriptID == "not_found" {
		return nil, errors.New("script not found")
	}

	// Create response with mock data
	response := &GetScriptResponse{
		ScriptID: req.ScriptID,
		UserID:   "IZ0MRfB2", // Mock user ID
		Customer: "AMD",
		Topic:    "Discovery call",
		Script:   "Hello, how are you? I am calling to discuss our product...",
	}

	return response, nil
}

// DeleteCustomScripts deletes custom scripts for a specific user
func (s *MeetingsService) DeleteCustomScripts(ctx context.Context, req DeleteScriptId) (*DeleteScriptResponse, error) {
	// Validate input
	if len(req.ScriptIDs) == 0 {
		return nil, errors.New("script_ids cannot be empty")
	}

	// TODO: In a real implementation, we would:
	// 1. Query the database to find and delete scripts with the given IDs
	// 2. Return the number of scripts deleted
	// 3. Handle errors and ensure the user has permission to delete these scripts

	// Mock implementation - simulate deleting scripts from a database
	deletedCount := len(req.ScriptIDs)

	// Create response
	response := &DeleteScriptResponse{
		Success: true,
		Message: fmt.Sprintf("Successfully deleted %d script(s)", deletedCount),
		Count:   deletedCount,
	}

	return response, nil
}
