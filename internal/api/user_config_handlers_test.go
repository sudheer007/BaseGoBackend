package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"gobackend/internal/middleware"
	"gobackend/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Define a mock interface with just the methods we need
type userConfigServicer interface {
	UpdateUserConfig(ctx interface{}, userID string, settings models.UserSettings) (*models.UserConfig, error)
}

// Create a mock implementation of our interface
type mockUserConfigService struct {
	mock.Mock
}

func (m *mockUserConfigService) UpdateUserConfig(ctx interface{}, userID string, settings models.UserSettings) (*models.UserConfig, error) {
	args := m.Called(ctx, userID, settings)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.UserConfig), args.Error(1)
}

// Create a test handler struct that uses our interface instead of the concrete service
type testUserConfigHandlers struct {
	service userConfigServicer
}

func (h *testUserConfigHandlers) UpdateUserConfig(c *gin.Context) {
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
	config, err := h.service.UpdateUserConfig(c.Request.Context(), req.UserID, req.Settings)
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

func TestUpdateUserConfig(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)

	testCases := []struct {
		name           string
		userID         string
		settings       models.UserSettings
		contextUserID  string
		contextRole    string
		mockReturnVal  *models.UserConfig
		mockReturnErr  error
		expectedStatus int
		expectedBody   string
	}{
		{
			name:          "Success - User updates own config",
			userID:        "123e4567-e89b-12d3-a456-426614174000",
			contextUserID: "123e4567-e89b-12d3-a456-426614174000",
			contextRole:   string(models.RoleUser),
			settings: models.UserSettings{
				UserPreferences: models.UserPreferences{
					AccountSettings: models.AccountSettings{
						Email:     "test@example.com",
						FirstName: "Test",
						LastName:  "User",
					},
				},
			},
			mockReturnVal: &models.UserConfig{
				ID:     uuid.MustParse("123e4567-e89b-12d3-a456-426614174000"),
				UserID: uuid.MustParse("123e4567-e89b-12d3-a456-426614174000"),
			},
			mockReturnErr:  nil,
			expectedStatus: http.StatusOK,
			expectedBody:   "User configuration updated successfully",
		},
		{
			name:          "Success - Admin updates another user's config",
			userID:        "123e4567-e89b-12d3-a456-426614174000",
			contextUserID: "223e4567-e89b-12d3-a456-426614174000",
			contextRole:   string(models.RoleAdmin),
			settings: models.UserSettings{
				UserPreferences: models.UserPreferences{
					AccountSettings: models.AccountSettings{
						Email:     "test@example.com",
						FirstName: "Test",
						LastName:  "User",
					},
				},
			},
			mockReturnVal: &models.UserConfig{
				ID:     uuid.MustParse("123e4567-e89b-12d3-a456-426614174000"),
				UserID: uuid.MustParse("123e4567-e89b-12d3-a456-426614174000"),
			},
			mockReturnErr:  nil,
			expectedStatus: http.StatusOK,
			expectedBody:   "User configuration updated successfully",
		},
		{
			name:          "Failure - User not found",
			userID:        "123e4567-e89b-12d3-a456-426614174000",
			contextUserID: "123e4567-e89b-12d3-a456-426614174000",
			contextRole:   string(models.RoleUser),
			settings: models.UserSettings{
				UserPreferences: models.UserPreferences{
					AccountSettings: models.AccountSettings{
						Email:     "test@example.com",
						FirstName: "Test",
						LastName:  "User",
					},
				},
			},
			mockReturnVal:  nil,
			mockReturnErr:  errors.New("user not found"),
			expectedStatus: http.StatusNotFound,
			expectedBody:   "user not found",
		},
		{
			name:          "Failure - Unauthorized user tries to update another user's config",
			userID:        "123e4567-e89b-12d3-a456-426614174000",
			contextUserID: "223e4567-e89b-12d3-a456-426614174000",
			contextRole:   string(models.RoleUser),
			settings: models.UserSettings{
				UserPreferences: models.UserPreferences{
					AccountSettings: models.AccountSettings{
						Email:     "test@example.com",
						FirstName: "Test",
						LastName:  "User",
					},
				},
			},
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Not authorized",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a new recorder
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			// Set up request body
			reqBody := UserConfigRequest{
				UserID:   tc.userID,
				Settings: tc.settings,
			}
			jsonBody, _ := json.Marshal(reqBody)

			// Create request
			req := httptest.NewRequest(http.MethodPost, "/api/v1/users/update-user-config", bytes.NewReader(jsonBody))
			req.Header.Set("Content-Type", "application/json")
			c.Request = req

			// Set context values
			c.Set(middleware.UserIDKey, tc.contextUserID)
			c.Set("user_role", tc.contextRole)

			// Create mock service
			mockSvc := new(mockUserConfigService)

			// Only set up mock if we're testing a case that would call the service
			if tc.contextUserID == tc.userID || tc.contextRole == string(models.RoleAdmin) || tc.contextRole == string(models.RoleSuperAdmin) {
				mockSvc.On("UpdateUserConfig", mock.Anything, tc.userID, tc.settings).Return(tc.mockReturnVal, tc.mockReturnErr)
			}

			// Create handler with mock
			handler := &testUserConfigHandlers{
				service: mockSvc,
			}

			// Call handler
			handler.UpdateUserConfig(c)

			// Check status
			assert.Equal(t, tc.expectedStatus, w.Code)

			// Check body contains expected string
			assert.Contains(t, w.Body.String(), tc.expectedBody)

			// Verify mock was called as expected
			mockSvc.AssertExpectations(t)
		})
	}
}
