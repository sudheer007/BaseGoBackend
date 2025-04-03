package data

import (
	"context"
	"os"
	"sync"
	"time"

	"gobackend/internal/models"

	"github.com/go-pg/pg/v10"
	"github.com/google/uuid"
)

// MockOrganizationRepository is a mock implementation of the organization repository
type MockOrganizationRepository struct {
	organizations map[uuid.UUID]*models.Organization
	domains       map[string]uuid.UUID
	mu            sync.RWMutex
}

// NewMockOrganizationRepository creates a new mock organization repository
func NewMockOrganizationRepository() *MockOrganizationRepository {
	r := &MockOrganizationRepository{
		organizations: make(map[uuid.UUID]*models.Organization),
		domains:       make(map[string]uuid.UUID),
	}

	// Add some sample data
	tenantID := uuid.New()
	orgID := uuid.New()
	org := &models.Organization{
		ID:            orgID,
		Name:          "Example Organization",
		DisplayName:   "Example Org",
		Industry:      "Technology",
		Website:       "https://example.com",
		ContactEmail:  "contact@example.com",
		PrimaryDomain: "example.com",
		Status:        models.OrgStatusActive,
		MaxUsers:      100,
		TenantID:      tenantID,
		CreatedAt:     time.Now().Add(-24 * time.Hour),
		UpdatedAt:     time.Now().Add(-12 * time.Hour),
	}
	r.organizations[orgID] = org
	r.domains[org.PrimaryDomain] = orgID

	return r
}

// GetByID retrieves an organization by its ID
func (r *MockOrganizationRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Organization, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	org, exists := r.organizations[id]
	if !exists || org.DeletedAt != nil {
		return nil, ErrNotFound
	}

	// Return a copy to prevent modification of the original
	orgCopy := *org
	return &orgCopy, nil
}

// List retrieves a paginated list of organizations
func (r *MockOrganizationRepository) List(ctx context.Context, page, pageSize int) ([]*models.Organization, int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Collect non-deleted organizations
	var orgs []*models.Organization
	for _, org := range r.organizations {
		if org.DeletedAt == nil {
			orgCopy := *org
			orgs = append(orgs, &orgCopy)
		}
	}

	// Get total count
	total := len(orgs)

	// Apply pagination
	start := (page - 1) * pageSize
	end := start + pageSize
	if start >= total {
		return []*models.Organization{}, total, nil
	}
	if end > total {
		end = total
	}

	return orgs[start:end], total, nil
}

// Create inserts a new organization
func (r *MockOrganizationRepository) Create(ctx context.Context, org *models.Organization) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check for duplicate primary domain
	if _, exists := r.domains[org.PrimaryDomain]; exists {
		return ErrDuplicateRecord
	}

	// Set default values if not provided
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

	// Store the organization
	orgCopy := *org
	r.organizations[org.ID] = &orgCopy
	r.domains[org.PrimaryDomain] = org.ID

	return nil
}

// Update updates an existing organization
func (r *MockOrganizationRepository) Update(ctx context.Context, org *models.Organization) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if organization exists
	existingOrg, exists := r.organizations[org.ID]
	if !exists || existingOrg.DeletedAt != nil {
		return ErrNotFound
	}

	// Check if primary domain is changing and if it's already in use
	if existingOrg.PrimaryDomain != org.PrimaryDomain {
		if id, exists := r.domains[org.PrimaryDomain]; exists && id != org.ID {
			return ErrDuplicateRecord
		}
		// Remove old domain mapping
		delete(r.domains, existingOrg.PrimaryDomain)
		// Add new domain mapping
		r.domains[org.PrimaryDomain] = org.ID
	}

	// Set updated time
	org.UpdatedAt = time.Now()
	org.CreatedAt = existingOrg.CreatedAt

	// Store the updated organization
	orgCopy := *org
	r.organizations[org.ID] = &orgCopy

	return nil
}

// Delete soft-deletes an organization
func (r *MockOrganizationRepository) Delete(ctx context.Context, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if organization exists
	org, exists := r.organizations[id]
	if !exists || org.DeletedAt != nil {
		return ErrNotFound
	}

	// Perform soft delete
	now := time.Now()
	org.DeletedAt = &now
	org.UpdatedAt = now
	org.Status = models.OrgStatusInactive

	return nil
}

// GetByPrimaryDomain retrieves an organization by its primary domain
func (r *MockOrganizationRepository) GetByPrimaryDomain(ctx context.Context, domain string) (*models.Organization, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	id, exists := r.domains[domain]
	if !exists {
		return nil, ErrNotFound
	}

	org, exists := r.organizations[id]
	if !exists || org.DeletedAt != nil {
		return nil, ErrNotFound
	}

	// Return a copy to prevent modification of the original
	orgCopy := *org
	return &orgCopy, nil
}

// ExistsByPrimaryDomain checks if an organization exists with the given primary domain
func (r *MockOrganizationRepository) ExistsByPrimaryDomain(ctx context.Context, domain string) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	id, exists := r.domains[domain]
	if !exists {
		return false, nil
	}

	org, exists := r.organizations[id]
	if !exists || org.DeletedAt != nil {
		return false, nil
	}

	return true, nil
}

// UpdateOrganizationRepository to support mock DB
func NewOrganizationRepository(db *pg.DB) OrganizationRepositoryInterface {
	if os.Getenv("USE_MOCK_DB") == "true" {
		return NewMockOrganizationRepository()
	}
	return &OrganizationRepository{
		db: db,
	}
}

// Define an interface for organization repositories to support both real and mock implementations
type OrganizationRepositoryInterface interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.Organization, error)
	List(ctx context.Context, page, pageSize int) ([]*models.Organization, int, error)
	Create(ctx context.Context, org *models.Organization) error
	Update(ctx context.Context, org *models.Organization) error
	Delete(ctx context.Context, id uuid.UUID) error
	GetByPrimaryDomain(ctx context.Context, domain string) (*models.Organization, error)
	ExistsByPrimaryDomain(ctx context.Context, domain string) (bool, error)
}
