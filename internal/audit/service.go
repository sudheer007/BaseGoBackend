package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/go-pg/pg/v10"
	"github.com/google/uuid"
	"gobackend/internal/models"
)

// Service is the audit logging service
type Service struct {
	db *pg.DB
}

// NewService creates a new audit logging service
func NewService(db *pg.DB) *Service {
	return &Service{
		db: db,
	}
}

// Log records an audit log entry
func (s *Service) Log(ctx context.Context, log *models.AuditLog) error {
	// Ensure we have a valid ID
	if log.ID == uuid.Nil {
		log.ID = uuid.New()
	}

	// Ensure we have a valid timestamp
	if log.CreatedAt.IsZero() {
		log.CreatedAt = time.Now()
	}

	// Insert the audit log entry
	_, err := s.db.Model(log).Insert()
	if err != nil {
		return fmt.Errorf("failed to insert audit log: %w", err)
	}

	return nil
}

// LogAction is a convenience method for logging an action
func (s *Service) LogAction(
	ctx context.Context,
	tenantID uuid.UUID,
	userID uuid.UUID,
	action models.AuditAction,
	resourceType string,
	resourceID string,
	description string,
	ipAddress string,
	userAgent string,
) error {
	log := &models.AuditLog{
		ID:           uuid.New(),
		TenantID:     tenantID,
		UserID:       userID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Description:  description,
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		Succeeded:    true,
		CreatedAt:    time.Now(),
	}

	return s.Log(ctx, log)
}

// LogChange records a change to a resource
func (s *Service) LogChange(
	ctx context.Context,
	tenantID uuid.UUID,
	userID uuid.UUID,
	action models.AuditAction,
	resourceType string,
	resourceID string,
	description string,
	oldValue interface{},
	newValue interface{},
	ipAddress string,
	userAgent string,
) error {
	log := &models.AuditLog{
		ID:           uuid.New(),
		TenantID:     tenantID,
		UserID:       userID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Description:  description,
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		Succeeded:    true,
		CreatedAt:    time.Now(),
	}

	// Set old and new values
	if oldValue != nil {
		if err := log.SetOldValue(oldValue); err != nil {
			return err
		}
	}

	if newValue != nil {
		if err := log.SetNewValue(newValue); err != nil {
			return err
		}
	}

	return s.Log(ctx, log)
}

// LogFailure records a failed action
func (s *Service) LogFailure(
	ctx context.Context,
	tenantID uuid.UUID,
	userID uuid.UUID,
	action models.AuditAction,
	resourceType string,
	resourceID string,
	description string,
	failReason string,
	ipAddress string,
	userAgent string,
) error {
	log := &models.AuditLog{
		ID:           uuid.New(),
		TenantID:     tenantID,
		UserID:       userID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Description:  description,
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		Succeeded:    false,
		FailReason:   failReason,
		CreatedAt:    time.Now(),
	}

	return s.Log(ctx, log)
}

// GetLogs retrieves audit logs for a tenant with pagination
func (s *Service) GetLogs(
	ctx context.Context,
	tenantID uuid.UUID,
	page int,
	pageSize int,
	filters map[string]interface{},
) ([]*models.AuditLog, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	query := s.db.Model((*models.AuditLog)(nil)).
		Where("tenant_id = ?", tenantID)

	// Apply filters
	for key, value := range filters {
		switch key {
		case "user_id":
			query = query.Where("user_id = ?", value)
		case "action":
			query = query.Where("action = ?", value)
		case "resource_type":
			query = query.Where("resource_type = ?", value)
		case "resource_id":
			query = query.Where("resource_id = ?", value)
		case "succeeded":
			query = query.Where("succeeded = ?", value)
		case "from_date":
			if date, ok := value.(time.Time); ok {
				query = query.Where("created_at >= ?", date)
			}
		case "to_date":
			if date, ok := value.(time.Time); ok {
				query = query.Where("created_at <= ?", date)
			}
		}
	}

	// Count total results
	count, err := query.Count()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count audit logs: %w", err)
	}

	// Get paginated results
	offset := (page - 1) * pageSize
	var logs []*models.AuditLog
	err = query.
		Order("created_at DESC").
		Limit(pageSize).
		Offset(offset).
		Select(&logs)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to retrieve audit logs: %w", err)
	}

	return logs, count, nil
}

// LogEvent records a generic event with custom metadata
func (s *Service) LogEvent(ctx context.Context, eventType string, metadata map[string]interface{}) error {
	// Extract user info from context if available
	var userID uuid.UUID
	var tenantID uuid.UUID
	
	// Use uuid.Nil for system events if user info is not available
	
	log := &models.AuditLog{
		ID:           uuid.New(),
		TenantID:     tenantID,
		UserID:       userID,
		Action:       models.AuditActionCustom,
		ResourceType: "event",
		ResourceID:   eventType,
		Description:  fmt.Sprintf("Event: %s", eventType),
		Succeeded:    true,
		CreatedAt:    time.Now(),
	}
	
	// Set metadata as new value
	if metadata != nil {
		if err := log.SetNewValue(metadata); err != nil {
			return err
		}
	}
	
	return s.Log(ctx, log)
} 