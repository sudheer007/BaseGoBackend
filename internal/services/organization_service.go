package services

import (
	"context"
	"errors"
	"time"

	"gobackend/internal/data"
	"gobackend/internal/models"

	"github.com/google/uuid"
)

// OrganizationService handles business logic for organizations
type OrganizationService struct {
	repo data.OrganizationRepositoryInterface
}

// NewOrganizationService creates a new organization service
func NewOrganizationService(repo data.OrganizationRepositoryInterface) *OrganizationService {
	return &OrganizationService{
		repo: repo,
	}
}

// GetByID returns an organization by its ID
func (s *OrganizationService) GetByID(ctx context.Context, id uuid.UUID) (*models.Organization, error) {
	return s.repo.GetByID(ctx, id)
}

// List returns a paginated list of organizations
func (s *OrganizationService) List(ctx context.Context, page, pageSize int) ([]*models.Organization, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	return s.repo.List(ctx, page, pageSize)
}

// Create creates a new organization
func (s *OrganizationService) Create(ctx context.Context, org *models.Organization) (*models.Organization, error) {
	// Validate required fields
	if org.Name == "" {
		return nil, errors.New("name is required")
	}
	if org.DisplayName == "" {
		return nil, errors.New("display name is required")
	}
	if org.PrimaryDomain == "" {
		return nil, errors.New("primary domain is required")
	}
	if org.ContactEmail == "" {
		return nil, errors.New("contact email is required")
	}
	if org.TenantID == uuid.Nil {
		return nil, errors.New("tenant ID is required")
	}

	// Check if an organization with the same primary domain already exists
	exists, err := s.repo.ExistsByPrimaryDomain(ctx, org.PrimaryDomain)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, errors.New("an organization with this primary domain already exists")
	}

	// Set default values
	if org.ID == uuid.Nil {
		org.ID = uuid.New()
	}
	if org.CreatedAt.IsZero() {
		org.CreatedAt = time.Now()
	}
	if org.UpdatedAt.IsZero() {
		org.UpdatedAt = time.Now()
	}
	if org.Status == "" {
		org.Status = models.OrgStatusPending
	}
	if org.MaxUsers == 0 {
		org.MaxUsers = 10 // Default max users
	}

	// Default settings if not provided
	if org.Settings.PasswordMinLength == 0 {
		org.Settings.PasswordMinLength = 12
	}
	if org.Settings.PasswordRotationDays == 0 {
		org.Settings.PasswordRotationDays = 90
	}
	if org.Settings.SessionTimeoutMinutes == 0 {
		org.Settings.SessionTimeoutMinutes = 60
	}
	if org.Settings.MaxLoginAttempts == 0 {
		org.Settings.MaxLoginAttempts = 5
	}
	if org.Settings.PasswordComplexity == "" {
		org.Settings.PasswordComplexity = "medium"
	}

	// Create the organization
	err = s.repo.Create(ctx, org)
	if err != nil {
		return nil, err
	}

	return org, nil
}

// Update updates an existing organization
func (s *OrganizationService) Update(ctx context.Context, org *models.Organization) (*models.Organization, error) {
	// Validate required fields
	if org.ID == uuid.Nil {
		return nil, errors.New("organization ID is required")
	}
	if org.Name == "" {
		return nil, errors.New("name is required")
	}
	if org.DisplayName == "" {
		return nil, errors.New("display name is required")
	}
	if org.PrimaryDomain == "" {
		return nil, errors.New("primary domain is required")
	}
	if org.ContactEmail == "" {
		return nil, errors.New("contact email is required")
	}

	// Get the existing organization to ensure it exists
	existing, err := s.repo.GetByID(ctx, org.ID)
	if err != nil {
		return nil, err
	}

	// Check if primary domain changed and already exists for another organization
	if existing.PrimaryDomain != org.PrimaryDomain {
		existingOrg, err := s.repo.GetByPrimaryDomain(ctx, org.PrimaryDomain)
		if err != nil && !errors.Is(err, data.ErrNotFound) {
			return nil, err
		}
		if existingOrg != nil && existingOrg.ID != org.ID {
			return nil, errors.New("an organization with this primary domain already exists")
		}
	}

	// Preserve fields that shouldn't be updated
	org.CreatedAt = existing.CreatedAt
	org.TenantID = existing.TenantID

	// Set updated time
	org.UpdatedAt = time.Now()

	// Update the organization
	err = s.repo.Update(ctx, org)
	if err != nil {
		return nil, err
	}

	return org, nil
}

// Delete deletes an organization by ID
func (s *OrganizationService) Delete(ctx context.Context, id uuid.UUID) error {
	if id == uuid.Nil {
		return errors.New("organization ID is required")
	}
	return s.repo.Delete(ctx, id)
}
