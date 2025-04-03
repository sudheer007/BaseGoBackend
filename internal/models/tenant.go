package models

import (
	"time"

	"github.com/go-pg/pg/v10/orm"
	"github.com/google/uuid"
)

// Tenant represents a tenant in the multi-tenant system
type Tenant struct {
	ID        uuid.UUID `pg:"id,type:uuid,pk"`
	Name      string    `pg:"name,notnull"`
	Domain    string    `pg:"domain,unique,notnull"`
	Active    bool      `pg:"active,notnull,default:true"`
	Settings  Settings  `pg:"settings,type:jsonb"`
	CreatedAt time.Time `pg:"created_at,notnull,default:now()"`
	UpdatedAt time.Time `pg:"updated_at,notnull,default:now()"`
}

// Settings represents tenant-specific settings
type Settings struct {
	MaxUsers          int    `json:"maxUsers"`
	StorageLimit      int64  `json:"storageLimit"`
	AllowedOrigins    string `json:"allowedOrigins"`
	EnableAuditLogs   bool   `json:"enableAuditLogs"`
	SecurityLevel     string `json:"securityLevel"`
	PasswordMinLength int    `json:"passwordMinLength"`
	PasswordExpiry    int    `json:"passwordExpiry"`
	MFARequired       bool   `json:"mfaRequired"`
}

// BeforeInsert hook is called before inserting a new tenant
func (t *Tenant) BeforeInsert(ctx orm.DB) error {
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	t.CreatedAt = time.Now()
	t.UpdatedAt = time.Now()
	return nil
}

// BeforeUpdate hook is called before updating a tenant
func (t *Tenant) BeforeUpdate(ctx orm.DB) error {
	t.UpdatedAt = time.Now()
	return nil
}

// TableName returns the name of the table for this model
func (t *Tenant) TableName() string {
	return "tenants"
} 