package services

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSetupMeeting(t *testing.T) {
	// Skip test for now until we implement proper mocking
	t.Skip("Skipping meetings service test until mocking implementation is completed")

	// Test cases
	testCases := []struct {
		name           string
		request        MeetingSetupRequest
		expectedError  bool
		expectedErrMsg string
	}{
		{
			name: "Valid meeting setup",
			request: MeetingSetupRequest{
				Meeting: MeetingSetup{
					UserID:       "ITRYOPY_",
					Customer:     "Sample Customer",
					CustomerMail: "customer@example.com",
					StartTime:    time.Now().Add(24 * time.Hour).Format("2006-01-02 15:04"),
					TimeZone:     "UTC",
					Topic:        "Project Discussion",
					Duration:     3600,
				},
			},
			expectedError: false,
		},
		{
			name: "Missing user_id",
			request: MeetingSetupRequest{
				Meeting: MeetingSetup{
					UserID:       "",
					Customer:     "Sample Customer",
					CustomerMail: "customer@example.com",
					StartTime:    time.Now().Add(24 * time.Hour).Format("2006-01-02 15:04"),
					TimeZone:     "UTC",
					Topic:        "Project Discussion",
					Duration:     3600,
				},
			},
			expectedError:  true,
			expectedErrMsg: "user_id is required",
		},
		{
			name: "Missing customer",
			request: MeetingSetupRequest{
				Meeting: MeetingSetup{
					UserID:       "ITRYOPY_",
					Customer:     "",
					CustomerMail: "customer@example.com",
					StartTime:    time.Now().Add(24 * time.Hour).Format("2006-01-02 15:04"),
					TimeZone:     "UTC",
					Topic:        "Project Discussion",
					Duration:     3600,
				},
			},
			expectedError:  true,
			expectedErrMsg: "customer is required",
		},
		{
			name: "Invalid start time",
			request: MeetingSetupRequest{
				Meeting: MeetingSetup{
					UserID:       "ITRYOPY_",
					Customer:     "Sample Customer",
					CustomerMail: "customer@example.com",
					StartTime:    "invalid-time-format",
					TimeZone:     "UTC",
					Topic:        "Project Discussion",
					Duration:     3600,
				},
			},
			expectedError:  true,
			expectedErrMsg: "invalid start_time format",
		},
		{
			name: "Past start time",
			request: MeetingSetupRequest{
				Meeting: MeetingSetup{
					UserID:       "ITRYOPY_",
					Customer:     "Sample Customer",
					CustomerMail: "customer@example.com",
					StartTime:    time.Now().Add(-24 * time.Hour).Format("2006-01-02 15:04"),
					TimeZone:     "UTC",
					Topic:        "Project Discussion",
					Duration:     3600,
				},
			},
			expectedError:  true,
			expectedErrMsg: "start_time must be in the future",
		},
		{
			name: "Invalid duration",
			request: MeetingSetupRequest{
				Meeting: MeetingSetup{
					UserID:       "ITRYOPY_",
					Customer:     "Sample Customer",
					CustomerMail: "customer@example.com",
					StartTime:    time.Now().Add(24 * time.Hour).Format("2006-01-02 15:04"),
					TimeZone:     "UTC",
					Topic:        "Project Discussion",
					Duration:     0,
				},
			},
			expectedError:  true,
			expectedErrMsg: "duration must be greater than 0",
		},
	}

	// Create service
	service := NewMeetingsService()

	// Run test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Execute the function
			resp, err := service.SetupMeeting(context.Background(), tc.request)

			// Check error condition
			if tc.expectedError {
				assert.Error(t, err)
				if tc.expectedErrMsg != "" {
					assert.Contains(t, err.Error(), tc.expectedErrMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.True(t, resp.Success)
				assert.NotEmpty(t, resp.MeetingID)
				assert.NotEmpty(t, resp.JoinURL)
			}
		})
	}
} 