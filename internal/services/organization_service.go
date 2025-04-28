package services

import (
	"context"
	"errors"
	"time"

	"gobackend/internal/data"
	"gobackend/internal/models"

	"github.com/go-pg/pg/v10"
	"github.com/google/uuid"
)

// OrganizationService handles business logic for organizations
type OrganizationService struct {
	repo data.OrganizationRepositoryInterface
	db   *pg.DB // Add DB access for operations not covered by repository
}

// NewOrganizationService creates a new organization service
func NewOrganizationService(repo data.OrganizationRepositoryInterface, db *pg.DB) *OrganizationService {
	return &OrganizationService{
		repo: repo,
		db:   db,
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

// ListByUser returns organizations accessible by a specific user
// For regular users, it will return only their assigned organization
// For super admins, it will return all managed organizations
func (s *OrganizationService) ListByUser(ctx context.Context, userID uuid.UUID, page, pageSize int) ([]*models.Organization, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	// Get the user to check their role
	var user models.User
	err := s.db.Model(&user).
		Where("id = ?", userID).
		Select()

	if err != nil {
		if err == pg.ErrNoRows {
			return nil, 0, errors.New("user not found")
		}
		return nil, 0, err
	}

	// If super admin, get managed organizations
	if user.IsSuperAdmin() {
		var orgs []*models.Organization
		var query *pg.Query

		// If the user has specific managed organizations
		if len(user.ManagedOrgIDs) > 0 {
			query = s.db.Model(&orgs).
				Where("id IN (?)", pg.In(user.ManagedOrgIDs))
		} else {
			// Super admin with no specific managed orgs can see all
			query = s.db.Model(&orgs)
		}

		total, err := query.
			Order("name ASC").
			Limit(pageSize).
			Offset((page - 1) * pageSize).
			SelectAndCount()

		if err != nil {
			return nil, 0, err
		}

		return orgs, total, nil
	}

	// For regular users, just get their assigned organization
	if user.OrganizationID == uuid.Nil {
		return nil, 0, nil
	}

	org, err := s.GetByID(ctx, user.OrganizationID)
	if err != nil {
		return nil, 0, err
	}

	return []*models.Organization{org}, 1, nil
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

// AssignOrganizationToUser adds an organization to a user's managed organizations
func (s *OrganizationService) AssignOrganizationToUser(ctx context.Context, userID, orgID uuid.UUID) error {
	// Verify the organization exists
	_, err := s.GetByID(ctx, orgID)
	if err != nil {
		return err
	}

	// Get the user
	var user models.User
	err = s.db.Model(&user).
		Where("id = ?", userID).
		Select()

	if err != nil {
		if err == pg.ErrNoRows {
			return errors.New("user not found")
		}
		return err
	}

	// Check if user is a super admin
	if !user.IsSuperAdmin() {
		return errors.New("only super admins can manage multiple organizations")
	}

	// Check if organization is already assigned
	for _, id := range user.ManagedOrgIDs {
		if id == orgID {
			return errors.New("organization is already assigned to this user")
		}
	}

	// Add organization to user's managed organizations
	user.ManagedOrgIDs = append(user.ManagedOrgIDs, orgID)
	user.UpdatedAt = time.Now()

	// Update the user
	_, err = s.db.Model(&user).
		Set("managed_org_ids = ?", user.ManagedOrgIDs).
		Set("updated_at = ?", user.UpdatedAt).
		Where("id = ?", user.ID).
		Update()

	return err
}

// UnassignOrganizationFromUser removes an organization from a user's managed organizations
func (s *OrganizationService) UnassignOrganizationFromUser(ctx context.Context, userID, orgID uuid.UUID) error {
	// Get the user
	var user models.User
	err := s.db.Model(&user).
		Where("id = ?", userID).
		Select()

	if err != nil {
		if err == pg.ErrNoRows {
			return errors.New("user not found")
		}
		return err
	}

	// Check if user is a super admin
	if !user.IsSuperAdmin() {
		return errors.New("only super admins can manage multiple organizations")
	}

	// Check if organization is assigned and remove it
	found := false
	var updatedOrgIDs []uuid.UUID
	for _, id := range user.ManagedOrgIDs {
		if id != orgID {
			updatedOrgIDs = append(updatedOrgIDs, id)
		} else {
			found = true
		}
	}

	if !found {
		return errors.New("organization is not assigned to this user")
	}

	// Update the user's managed organizations
	user.ManagedOrgIDs = updatedOrgIDs
	user.UpdatedAt = time.Now()

	// Update the user
	_, err = s.db.Model(&user).
		Set("managed_org_ids = ?", user.ManagedOrgIDs).
		Set("updated_at = ?", user.UpdatedAt).
		Where("id = ?", user.ID).
		Update()

	return err
}

// GetUsersManagedOrganizations returns the list of organizations managed by a user
func (s *OrganizationService) GetUsersManagedOrganizations(ctx context.Context, userID uuid.UUID) ([]*models.Organization, error) {
	// Get the user
	var user models.User
	err := s.db.Model(&user).
		Where("id = ?", userID).
		Select()

	if err != nil {
		if err == pg.ErrNoRows {
			return nil, errors.New("user not found")
		}
		return nil, err
	}

	// Check if user is a super admin
	if !user.IsSuperAdmin() {
		return nil, errors.New("only super admins can manage multiple organizations")
	}

	// If no managed organizations, return empty list
	if len(user.ManagedOrgIDs) == 0 {
		return []*models.Organization{}, nil
	}

	// Get all managed organizations
	var orgs []*models.Organization
	err = s.db.Model(&orgs).
		Where("id IN (?)", pg.In(user.ManagedOrgIDs)).
		Select()

	if err != nil {
		return nil, err
	}

	return orgs, nil
}
