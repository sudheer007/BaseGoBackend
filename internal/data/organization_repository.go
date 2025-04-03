package data

import (
	"context"
	"errors"
	"strings"
	"time"

	"gobackend/internal/models"

	"github.com/go-pg/pg/v10"
	"github.com/google/uuid"
)

// Common repository errors
var (
	ErrNotFound          = errors.New("record not found")
	ErrInvalidID         = errors.New("invalid ID")
	ErrDuplicateRecord   = errors.New("duplicate record")
	ErrDatabaseOperation = errors.New("database operation failed")
	ErrInvalidData       = errors.New("invalid data provided")
)

// OrganizationRepository handles database operations for organizations
type OrganizationRepository struct {
	db *pg.DB
}

// NewPostgresOrganizationRepository creates a new organization repository
func NewPostgresOrganizationRepository(db *pg.DB) *OrganizationRepository {
	return &OrganizationRepository{
		db: db,
	}
}

// GetByID retrieves an organization by its ID
func (r *OrganizationRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Organization, error) {
	org := new(models.Organization)
	err := r.db.ModelContext(ctx, org).
		Where("id = ? AND deleted_at IS NULL", id).
		Select()

	if err != nil {
		if err == pg.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return org, nil
}

// List retrieves a paginated list of organizations
func (r *OrganizationRepository) List(ctx context.Context, page, pageSize int) ([]*models.Organization, int, error) {
	var orgs []*models.Organization

	// Calculate the offset for pagination
	offset := (page - 1) * pageSize

	// Get total count
	total, err := r.db.ModelContext(ctx, &models.Organization{}).
		Where("deleted_at IS NULL").
		Count()
	if err != nil {
		return nil, 0, err
	}

	// Query with pagination
	err = r.db.ModelContext(ctx, &orgs).
		Where("deleted_at IS NULL").
		Order("created_at DESC").
		Limit(pageSize).
		Offset(offset).
		Select()

	if err != nil {
		return nil, 0, err
	}

	return orgs, total, nil
}

// Create inserts a new organization
func (r *OrganizationRepository) Create(ctx context.Context, org *models.Organization) error {
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

	// Perform insertion
	_, err := r.db.ModelContext(ctx, org).Insert()
	if err != nil {
		// Handle duplicate primary domain error
		if isDuplicateError(err, "organizations_primary_domain_key") {
			return ErrDuplicateRecord
		}
		return err
	}

	return nil
}

// Update updates an existing organization
func (r *OrganizationRepository) Update(ctx context.Context, org *models.Organization) error {
	// Set updated time
	org.UpdatedAt = time.Now()

	// Perform update
	res, err := r.db.ModelContext(ctx, org).
		WherePK().
		Where("deleted_at IS NULL").
		Update()

	if err != nil {
		// Handle duplicate primary domain error
		if isDuplicateError(err, "organizations_primary_domain_key") {
			return ErrDuplicateRecord
		}
		return err
	}

	if res.RowsAffected() == 0 {
		return ErrNotFound
	}

	return nil
}

// Delete soft-deletes an organization
func (r *OrganizationRepository) Delete(ctx context.Context, id uuid.UUID) error {
	now := time.Now()

	// Perform soft delete
	res, err := r.db.ModelContext(ctx, (*models.Organization)(nil)).
		Set("deleted_at = ?", now).
		Set("updated_at = ?", now).
		Set("status = ?", models.OrgStatusInactive).
		Where("id = ? AND deleted_at IS NULL", id).
		Update()

	if err != nil {
		return err
	}

	if res.RowsAffected() == 0 {
		return ErrNotFound
	}

	return nil
}

// GetByPrimaryDomain retrieves an organization by its primary domain
func (r *OrganizationRepository) GetByPrimaryDomain(ctx context.Context, domain string) (*models.Organization, error) {
	org := new(models.Organization)
	err := r.db.ModelContext(ctx, org).
		Where("primary_domain = ? AND deleted_at IS NULL", domain).
		Select()

	if err != nil {
		if err == pg.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return org, nil
}

// ExistsByPrimaryDomain checks if an organization exists with the given primary domain
func (r *OrganizationRepository) ExistsByPrimaryDomain(ctx context.Context, domain string) (bool, error) {
	exists, err := r.db.ModelContext(ctx, (*models.Organization)(nil)).
		Where("primary_domain = ? AND deleted_at IS NULL", domain).
		Exists()

	return exists, err
}

// isDuplicateError checks if the error is a duplicate key error
func isDuplicateError(err error, constraintName string) bool {
	return err != nil && strings.Contains(err.Error(), "duplicate key") &&
		strings.Contains(err.Error(), constraintName)
}
