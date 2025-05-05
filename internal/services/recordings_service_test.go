package services

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestGetUserRecordings(t *testing.T) {
	// Skip test for now until we implement proper mocking
	t.Skip("Skipping recordings service test until mocking implementation is completed")

	// Test cases
	testCases := []struct {
		name           string
		request        GetUserRecordingsRequest
		expectedError  bool
		expectedErrMsg string
	}{
		{
			name: "Valid request",
			request: GetUserRecordingsRequest{
				UserID: uuid.New(),
				Limit:  10,
				Offset: 0,
			},
			expectedError: false,
		},
		{
			name: "Missing user ID",
			request: GetUserRecordingsRequest{
				UserID: uuid.Nil,
				Limit:  10,
				Offset: 0,
			},
			expectedError:  true,
			expectedErrMsg: "user_id is required",
		},
		{
			name: "Negative limit",
			request: GetUserRecordingsRequest{
				UserID: uuid.New(),
				Limit:  -5,
				Offset: 0,
			},
			expectedError: false, // Should auto-correct to default value
		},
		{
			name: "Negative offset",
			request: GetUserRecordingsRequest{
				UserID: uuid.New(),
				Limit:  10,
				Offset: -5,
			},
			expectedError: false, // Should auto-correct to default value
		},
	}

	// Create service
	service := NewRecordingsService()

	// Run test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Execute the function
			resp, err := service.GetUserRecordings(context.Background(), tc.request)

			// Check error condition
			if tc.expectedError {
				assert.Error(t, err)
				if tc.expectedErrMsg != "" {
					assert.Equal(t, tc.expectedErrMsg, err.Error())
				}
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.NotNil(t, resp.Recordings)
				assert.GreaterOrEqual(t, resp.Total, 0)
			}
		})
	}
} 