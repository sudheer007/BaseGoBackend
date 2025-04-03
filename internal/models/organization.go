package models

import (
	"time"

	"github.com/go-pg/pg/v10/orm"
	"github.com/google/uuid"
)

// Organization represents a company or organization in the system
type Organization struct {
	ID             uuid.UUID       `pg:"id,type:uuid,pk"`
	Name           string          `pg:"name,notnull"`
	DisplayName    string          `pg:"display_name,notnull"`
	Industry       string          `pg:"industry"`
	Website        string          `pg:"website"`
	Logo           string          `pg:"logo"`
	Address        Address         `pg:"address,type:jsonb"`
	ContactEmail   string          `pg:"contact_email,notnull"`
	ContactPhone   string          `pg:"contact_phone"`
	PrimaryDomain  string          `pg:"primary_domain,unique,notnull"`
	AllowedDomains []string        `pg:"allowed_domains,type:jsonb"`
	Status         OrgStatus       `pg:"status,type:text,notnull"`
	Settings       OrgSettings     `pg:"settings,type:jsonb"`
	Subscription   OrgSubscription `pg:"subscription,type:jsonb"`
	MaxUsers       int             `pg:"max_users,notnull,default:10"`
	TenantID       uuid.UUID       `pg:"tenant_id,type:uuid,notnull"` // Link to tenant
	CreatedAt      time.Time       `pg:"created_at,notnull,default:now()"`
	UpdatedAt      time.Time       `pg:"updated_at,notnull,default:now()"`
	DeletedAt      *time.Time      `pg:"deleted_at"`

	// Relations
	Tenant *Tenant `pg:"rel:has-one,fk:tenant_id"`
	Teams  []*Team `pg:"rel:has-many,join_fk:organization_id"`
	Users  []*User `pg:"rel:has-many,join_fk:organization_id"`
}

// OrgStatus represents the status of an organization
type OrgStatus string

// Organization statuses
const (
	OrgStatusActive    OrgStatus = "active"
	OrgStatusInactive  OrgStatus = "inactive"
	OrgStatusSuspended OrgStatus = "suspended"
	OrgStatusPending   OrgStatus = "pending"
)

// Address represents a physical address
type Address struct {
	Street     string `json:"street"`
	City       string `json:"city"`
	State      string `json:"state"`
	PostalCode string `json:"postalCode"`
	Country    string `json:"country"`
}

// OrgSettings represents organization-specific settings
type OrgSettings struct {
	RequireMFA              bool   `json:"requireMfa"`
	PasswordRotationDays    int    `json:"passwordRotationDays"`
	PasswordMinLength       int    `json:"passwordMinLength"`
	PasswordComplexity      string `json:"passwordComplexity"` // low, medium, high
	MaxLoginAttempts        int    `json:"maxLoginAttempts"`
	EnableIPRestriction     bool   `json:"enableIpRestriction"`
	AllowedIPRanges         string `json:"allowedIpRanges"`
	SessionTimeoutMinutes   int    `json:"sessionTimeoutMinutes"`
	EnableUserAudit         bool   `json:"enableUserAudit"`
	EnableResourceAudit     bool   `json:"enableResourceAudit"`
	EnableFieldLevelAudit   bool   `json:"enableFieldLevelAudit"`
	AllowCrossOrgDataAccess bool   `json:"allowCrossOrgDataAccess"`
}

// OrgSubscription represents subscription details for the organization
type OrgSubscription struct {
	Plan            string     `json:"plan"` // free, basic, premium, enterprise
	StartDate       time.Time  `json:"startDate"`
	EndDate         time.Time  `json:"endDate"`
	AutoRenew       bool       `json:"autoRenew"`
	PaymentMethod   string     `json:"paymentMethod"`
	BillingInterval string     `json:"billingInterval"` // monthly, yearly
	BillingEmail    string     `json:"billingEmail"`
	CancelledAt     *time.Time `json:"cancelledAt"`
}

// BeforeInsert hook is called before inserting a new organization
func (o *Organization) BeforeInsert(ctx orm.DB) error {
	if o.ID == uuid.Nil {
		o.ID = uuid.New()
	}
	o.CreatedAt = time.Now()
	o.UpdatedAt = time.Now()
	return nil
}

// BeforeUpdate hook is called before updating an organization
func (o *Organization) BeforeUpdate(ctx orm.DB) error {
	o.UpdatedAt = time.Now()
	return nil
}

// TableName returns the name of the table for this model
func (o *Organization) TableName() string {
	return "organizations"
}

// GetUserCount returns the number of users in the organization
func (o *Organization) GetUserCount(ctx orm.DB) (int, error) {
	count, err := ctx.Model((*User)(nil)).
		Where("organization_id = ? AND deleted_at IS NULL", o.ID).
		Count()
	return count, err
}

// HasAvailableUserSlots checks if the organization has available user slots
func (o *Organization) HasAvailableUserSlots(ctx orm.DB) (bool, error) {
	count, err := o.GetUserCount(ctx)
	if err != nil {
		return false, err
	}
	return count < o.MaxUsers, nil
}

// IsActive returns whether the organization is active
func (o *Organization) IsActive() bool {
	return o.Status == OrgStatusActive
}

// SoftDelete marks the organization as deleted
func (o *Organization) SoftDelete(ctx orm.DB) error {
	now := time.Now()
	o.DeletedAt = &now
	o.Status = OrgStatusInactive
	_, err := ctx.Model(o).
		Set("deleted_at = ?", now).
		Set("status = ?", OrgStatusInactive).
		Set("updated_at = ?", now).
		Where("id = ?", o.ID).
		Update()
	return err
}
