package models

import (
	"encoding/json"
	"time"

	"github.com/go-pg/pg/v10/orm"
	"github.com/google/uuid"
)

// AuditAction represents the type of action being audited
type AuditAction string

// Define audit action types
const (
	AuditActionCreate AuditAction = "create"
	AuditActionRead   AuditAction = "read"
	AuditActionUpdate AuditAction = "update"
	AuditActionDelete AuditAction = "delete"
	AuditActionLogin  AuditAction = "login"
	AuditActionLogout AuditAction = "logout"
	AuditActionFailed AuditAction = "failed"
)

// AuditLog represents an audit trail entry in the system
type AuditLog struct {
	ID          uuid.UUID      `pg:"id,type:uuid,pk"`
	TenantID    uuid.UUID      `pg:"tenant_id,type:uuid,notnull"`
	UserID      uuid.UUID      `pg:"user_id,type:uuid"`
	Action      AuditAction    `pg:"action,type:text,notnull"`
	ResourceType string        `pg:"resource_type,notnull"` // e.g., "user", "tenant", "document"
	ResourceID   string        `pg:"resource_id"`           // ID of the affected resource
	Description  string        `pg:"description"`           // Human-readable description
	OldValue     string        `pg:"old_value,type:jsonb"`  // Previous state (JSON)
	NewValue     string        `pg:"new_value,type:jsonb"`  // New state (JSON)
	IPAddress    string        `pg:"ip_address"`
	UserAgent    string        `pg:"user_agent"`
	Succeeded    bool          `pg:"succeeded,notnull"`
	FailReason   string        `pg:"fail_reason"`
	CreatedAt    time.Time     `pg:"created_at,notnull,default:now()"`
}

// BeforeInsert hook is called before inserting a new audit log entry
func (a *AuditLog) BeforeInsert(ctx orm.DB) error {
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	a.CreatedAt = time.Now()
	return nil
}

// TableName returns the name of the table for this model
func (a *AuditLog) TableName() string {
	return "audit_logs"
}

// NewAuditLog creates a new audit log entry
func NewAuditLog(tenantID uuid.UUID, userID uuid.UUID, action AuditAction, resourceType, resourceID string) *AuditLog {
	return &AuditLog{
		ID:           uuid.New(),
		TenantID:     tenantID,
		UserID:       userID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Succeeded:    true,
		CreatedAt:    time.Now(),
	}
}

// SetOldValue sets the old value from an object
func (a *AuditLog) SetOldValue(value interface{}) error {
	if value == nil {
		return nil
	}
	
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	
	a.OldValue = string(data)
	return nil
}

// SetNewValue sets the new value from an object
func (a *AuditLog) SetNewValue(value interface{}) error {
	if value == nil {
		return nil
	}
	
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	
	a.NewValue = string(data)
	return nil
}

// SetFailed marks the audit log as failed with a reason
func (a *AuditLog) SetFailed(reason string) {
	a.Succeeded = false
	a.FailReason = reason
} 