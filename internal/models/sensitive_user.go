package models

import (
	"time"

	"github.com/google/uuid"
)

// SensitiveUserData represents sensitive user information that should be encrypted
type SensitiveUserData struct {
	ID            string    `json:"id"`
	UserID        string    `json:"user_id"`
	TaxID         string    `json:"tax_id,omitempty"`
	SSN           string    `json:"ssn,omitempty"`
	HealthData    string    `json:"health_data,omitempty"`
	FinancialInfo string    `json:"financial_info,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	TenantID      string    `json:"tenant_id"`
	IsEncrypted   bool      `json:"-"`
}

// NewSensitiveUserData creates a new sensitive user data record
func NewSensitiveUserData(userID, tenantID string) *SensitiveUserData {
	return &SensitiveUserData{
		ID:        uuid.New().String(),
		UserID:    userID,
		TenantID:  tenantID,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// SensitiveUserFields returns a map of field names that should be encrypted
func SensitiveUserFields() []string {
	return []string{
		"TaxID",
		"SSN",
		"HealthData",
		"FinancialInfo",
	}
}

// Validate validates the sensitive user data
func (s *SensitiveUserData) Validate() error {
	if s.UserID == "" {
		return NewValidationError("user_id is required")
	}

	if s.TenantID == "" {
		return NewValidationError("tenant_id is required")
	}

	return nil
}

// BeforeCreate is called before creating a sensitive user data record
func (s *SensitiveUserData) BeforeCreate() {
	if s.ID == "" {
		s.ID = uuid.New().String()
	}
	now := time.Now()
	s.CreatedAt = now
	s.UpdatedAt = now
}

// BeforeUpdate is called before updating a sensitive user data record
func (s *SensitiveUserData) BeforeUpdate() {
	s.UpdatedAt = time.Now()
}

// TableName returns the table name for the model
func (s *SensitiveUserData) TableName() string {
	return "sensitive_user_data"
}
