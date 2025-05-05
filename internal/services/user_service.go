package services

import (
	"context"
	"errors"

	"gobackend/internal/audit"
	"gobackend/internal/data"
	"gobackend/internal/models"

	"github.com/google/uuid"
)

// UserService provides user-related functionality
type UserService struct {
	userRepo *data.UserRepository
	auditSvc *audit.Service
}

// NewUserService creates a new user service
func NewUserService(userRepo *data.UserRepository, auditSvc *audit.Service) *UserService {
	return &UserService{
		userRepo: userRepo,
		auditSvc: auditSvc,
	}
}

// AddUserRequest represents the request to add a new user
type AddUserRequest struct {
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email" binding:"required,email"`
	Password  string `json:"password" binding:"required,min=8"`
}

// AddUserResponse represents the response after adding a user
type AddUserResponse struct {
	Message string    `json:"message"`
	UserID  uuid.UUID `json:"user_id"`
}

// AddUser creates a new user in the database
func (s *UserService) AddUser(ctx context.Context, req AddUserRequest, tenantID, orgID uuid.UUID, creatorID uuid.UUID, ipAddress, userAgent string) (*AddUserResponse, error) {
	// Validate input
	if req.Email == "" {
		return nil, errors.New("email is required")
	}
	if req.Password == "" {
		return nil, errors.New("password is required")
	}

	// Create user model
	user := &models.User{
		TenantID:       tenantID,
		OrganizationID: orgID,
		Email:          req.Email,
		Password:       req.Password, // Will be hashed by BeforeInsert hook
		FirstName:      req.FirstName,
		LastName:       req.LastName,
		Status:         models.UserStatusActive,
		Active:         true,
	}

	// Add user to database
	err := s.userRepo.AddUser(ctx, user)
	if err != nil {
		if errors.Is(err, data.ErrEmailAlreadyExists) {
			return nil, err
		}
		return nil, errors.New("failed to create user: " + err.Error())
	}

	// Log user creation for audit
	if s.auditSvc != nil {
		s.auditSvc.LogAction(ctx, tenantID, creatorID, models.AuditActionCreate,
			"user", user.ID.String(), "User created through API",
			ipAddress, userAgent)
	}

	// Return success response
	return &AddUserResponse{
		Message: "User created successfully",
		UserID:  user.ID,
	}, nil
}

// GetUserByID retrieves a user by ID
func (s *UserService) GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	return s.userRepo.GetUserByID(ctx, id)
}

// GetUserByEmail retrieves a user by email
func (s *UserService) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	return s.userRepo.GetUserByEmail(ctx, email)
}
