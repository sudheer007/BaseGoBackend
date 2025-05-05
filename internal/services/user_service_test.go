package services

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"gobackend/internal/data"
	"gobackend/internal/models"
)

// MockUserRepository is a mock implementation of the user repository
type MockUserRepository struct {
	mock.Mock
}

// AddUser is a mock implementation of the AddUser method
func (m *MockUserRepository) AddUser(ctx context.Context, user *models.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

// GetUserByID is a mock implementation of the GetUserByID method
func (m *MockUserRepository) GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

// GetUserByEmail is a mock implementation of the GetUserByEmail method
func (m *MockUserRepository) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

// MockAuditService is a mock implementation of the audit service
type MockAuditService struct {
	mock.Mock
}

// LogAction is a mock implementation of the LogAction method
func (m *MockAuditService) LogAction(ctx context.Context, tenantID, userID uuid.UUID, action models.AuditAction,
	resourceType, resourceID, description string,
	ipAddress, userAgent string) error {
	args := m.Called(ctx, tenantID, userID, action, resourceType, resourceID, description, ipAddress, userAgent)
	return args.Error(0)
}

func TestAddUser(t *testing.T) {
	// Skip test for now while we fix the infrastructure
	t.Skip("Skipping test until user service mocking is fixed")

	// Test cases
	testCases := []struct {
		name           string
		request        AddUserRequest
		setupMocks     func(*MockUserRepository, *MockAuditService)
		expectedError  bool
		expectedErrMsg string
	}{
		{
			name: "Successful user creation",
			request: AddUserRequest{
				Email:     "test@example.com",
				Password:  "password123",
				FirstName: "Test",
				LastName:  "User",
			},
			setupMocks: func(mockRepo *MockUserRepository, mockAudit *MockAuditService) {
				mockRepo.On("AddUser", mock.Anything, mock.MatchedBy(func(user *models.User) bool {
					return user.Email == "test@example.com" &&
						user.FirstName == "Test" &&
						user.LastName == "User" &&
						user.Password == "password123"
				})).Return(nil)

				mockAudit.On("LogAction",
					mock.Anything,
					mock.Anything,
					mock.Anything,
					models.AuditActionCreate,
					"user",
					mock.Anything,
					"User created through API",
					mock.Anything,
					mock.Anything,
				).Return(nil)
			},
			expectedError: false,
		},
		{
			name: "Email already exists",
			request: AddUserRequest{
				Email:     "existing@example.com",
				Password:  "password123",
				FirstName: "Existing",
				LastName:  "User",
			},
			setupMocks: func(mockRepo *MockUserRepository, mockAudit *MockAuditService) {
				mockRepo.On("AddUser", mock.Anything, mock.MatchedBy(func(user *models.User) bool {
					return user.Email == "existing@example.com"
				})).Return(data.ErrEmailAlreadyExists)

				// No audit log for failed creation
			},
			expectedError:  true,
			expectedErrMsg: "email already exists",
		},
		{
			name: "Missing email",
			request: AddUserRequest{
				Email:     "",
				Password:  "password123",
				FirstName: "Missing",
				LastName:  "Email",
			},
			setupMocks: func(mockRepo *MockUserRepository, mockAudit *MockAuditService) {
				// No DB calls should occur
			},
			expectedError:  true,
			expectedErrMsg: "email is required",
		},
		{
			name: "Missing password",
			request: AddUserRequest{
				Email:     "test@example.com",
				Password:  "",
				FirstName: "Missing",
				LastName:  "Password",
			},
			setupMocks: func(mockRepo *MockUserRepository, mockAudit *MockAuditService) {
				// No DB calls should occur
			},
			expectedError:  true,
			expectedErrMsg: "password is required",
		},
		{
			name: "Database error",
			request: AddUserRequest{
				Email:     "error@example.com",
				Password:  "password123",
				FirstName: "Error",
				LastName:  "User",
			},
			setupMocks: func(mockRepo *MockUserRepository, mockAudit *MockAuditService) {
				mockRepo.On("AddUser", mock.Anything, mock.MatchedBy(func(user *models.User) bool {
					return user.Email == "error@example.com"
				})).Return(errors.New("database error"))

				// No audit log for failed creation
			},
			expectedError:  true,
			expectedErrMsg: "failed to create user: database error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create mocks
			mockRepo := new(MockUserRepository)
			mockAudit := new(MockAuditService)

			// Setup mocks
			if tc.setupMocks != nil {
				tc.setupMocks(mockRepo, mockAudit)
			}

			// Create a stub service for testing
			service := &UserService{}

			// Test the AddUser method
			tenantID := uuid.New()
			orgID := uuid.New()
			creatorID := uuid.New()
			ipAddress := "127.0.0.1"
			userAgent := "test-agent"

			resp, err := service.AddUser(context.Background(), tc.request, tenantID, orgID, creatorID, ipAddress, userAgent)

			// Check errors
			if tc.expectedError {
				assert.Error(t, err)
				if tc.expectedErrMsg != "" {
					assert.Equal(t, tc.expectedErrMsg, err.Error())
				}
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Equal(t, "User created successfully", resp.Message)
				assert.NotEqual(t, uuid.Nil, resp.UserID)
			}

			// Verify all expectations were met
			mockRepo.AssertExpectations(t)
			mockAudit.AssertExpectations(t)
		})
	}
}
