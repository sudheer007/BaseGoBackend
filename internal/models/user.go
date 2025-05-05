package models

import (
	"errors"
	"time"

	"github.com/go-pg/pg/v10/orm"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// Role represents the user's role in the system
type Role string

// Available roles - updated for enterprise hierarchy
const (
	RoleSuperAdmin Role = "super_admin" // Access to multiple organizations
	RoleAdmin      Role = "admin"       // Organization-level administrator
	RoleManager    Role = "manager"     // Team-level manager
	RoleUser       Role = "user"        // Regular user
	RoleReadOnly   Role = "readonly"    // Read-only user
)

// User represents a user in the system
type User struct {
	ID              uuid.UUID  `pg:"id,type:uuid,pk"`
	TenantID        uuid.UUID  `pg:"tenant_id,type:uuid,notnull"`
	OrganizationID  uuid.UUID  `pg:"organization_id,type:uuid,notnull"`
	Email           string     `pg:"email,unique,notnull"`
	PasswordHash    string     `pg:"password_hash,notnull"`
	FirstName       string     `pg:"first_name"`
	LastName        string     `pg:"last_name"`
	PhoneNumber     string     `pg:"phone_number"`
	JobTitle        string     `pg:"job_title"`
	Department      string     `pg:"department"`
	ProfileImage    string     `pg:"profile_image"`
	Role            Role       `pg:"role,type:text,notnull"`
	Status          UserStatus `pg:"status,type:text,notnull,default:'active'"`
	Active          bool       `pg:"active,notnull,default:true"`
	EmailVerified   bool       `pg:"email_verified,notnull,default:false"`
	MFAEnabled      bool       `pg:"mfa_enabled,notnull,default:false"`
	MFASecret       string     `pg:"mfa_secret"`
	MFAType         string     `pg:"mfa_type"` // app, sms, email
	LoginAttempts   int        `pg:"login_attempts,notnull,default:0"`
	LastLogin       time.Time  `pg:"last_login"`
	PasswordChanged time.Time  `pg:"password_changed,notnull"`
	FailedAttempts  int        `pg:"failed_attempts,notnull,default:0"`
	LockedUntil     time.Time  `pg:"locked_until"`
	LastActivity    time.Time  `pg:"last_activity"`
	APIKey          string     `pg:"api_key"`
	APIKeyExpiry    time.Time  `pg:"api_key_expiry"`
	Preferences     UserPrefs  `pg:"preferences,type:jsonb"`
	CreatedAt       time.Time  `pg:"created_at,notnull,default:now()"`
	UpdatedAt       time.Time  `pg:"updated_at,notnull,default:now()"`
	DeletedAt       *time.Time `pg:"deleted_at"`

	// OAuth provider fields
	GoogleID        string     `pg:"google_id"`
	OAuthProvider   string     `pg:"oauth_provider"` // google, github, etc.

	// OrgSuperAdmin flag allows a user to manage multiple organizations
	// This is separate from Role to allow for more fine-grained control
	OrgSuperAdmin bool `pg:"org_super_admin,notnull,default:false"`

	// Managed organizations for super admins
	ManagedOrgIDs []uuid.UUID `pg:"managed_org_ids,type:uuid[]"`

	// Relations
	Tenant       *Tenant       `pg:"rel:has-one,fk:tenant_id"`
	Organization *Organization `pg:"rel:has-one,fk:organization_id"`
	Teams        []*Team       `pg:"many2many:team_members"`

	// Fields not stored in the database
	Password string `pg:"-"`
}

// UserStatus represents the status of a user account
type UserStatus string

// Available user statuses
const (
	UserStatusActive      UserStatus = "active"
	UserStatusInactive    UserStatus = "inactive"
	UserStatusSuspended   UserStatus = "suspended"
	UserStatusPending     UserStatus = "pending"
	UserStatusDeactivated UserStatus = "deactivated"
)

// UserPrefs represents user preferences
type UserPrefs struct {
	Theme            string `json:"theme"`            // light, dark, system
	Language         string `json:"language"`         // en, fr, etc.
	Timezone         string `json:"timezone"`         // America/New_York, etc.
	NotifyEmail      bool   `json:"notifyEmail"`      // Email notifications
	NotifyPush       bool   `json:"notifyPush"`       // Push notifications
	NotifySMS        bool   `json:"notifySms"`        // SMS notifications
	DisplayDensity   string `json:"displayDensity"`   // compact, comfortable, etc.
	DefaultDashboard string `json:"defaultDashboard"` // Default dashboard ID
}

// BeforeInsert hook is called before inserting a new user
func (u *User) BeforeInsert(ctx orm.DB) error {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}

	if u.Password != "" {
		hash, err := u.HashPassword(u.Password)
		if err != nil {
			return err
		}
		u.PasswordHash = hash
		u.PasswordChanged = time.Now()
	}

	// Set default status if not provided
	if u.Status == "" {
		u.Status = UserStatusActive
	}

	u.CreatedAt = time.Now()
	u.UpdatedAt = time.Now()
	return nil
}

// BeforeUpdate hook is called before updating a user
func (u *User) BeforeUpdate(ctx orm.DB) error {
	if u.Password != "" {
		hash, err := u.HashPassword(u.Password)
		if err != nil {
			return err
		}
		u.PasswordHash = hash
		u.PasswordChanged = time.Now()
	}

	u.UpdatedAt = time.Now()
	return nil
}

// HashPassword creates a bcrypt hash of the password
func (u *User) HashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("password cannot be empty")
	}

	// Use a high cost factor for security
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(hash), err
}

// CheckPassword checks if the provided password is correct
func (u *User) CheckPassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password))
	return err == nil
}

// FullName returns the user's full name
func (u *User) FullName() string {
	if u.FirstName != "" && u.LastName != "" {
		return u.FirstName + " " + u.LastName
	}
	if u.FirstName != "" {
		return u.FirstName
	}
	if u.LastName != "" {
		return u.LastName
	}
	return ""
}

// TableName returns the name of the table for this model
func (u *User) TableName() string {
	return "users"
}

// IsLocked returns whether the user account is locked
func (u *User) IsLocked() bool {
	return !u.LockedUntil.IsZero() && time.Now().Before(u.LockedUntil)
}

// ShouldResetPassword returns whether the user should reset their password
// based on the password age policy (e.g., 90 days)
func (u *User) ShouldResetPassword(maxAgeDays int) bool {
	if maxAgeDays <= 0 {
		return false
	}

	// Calculate password age
	passwordAge := time.Since(u.PasswordChanged)
	maxAge := time.Duration(maxAgeDays) * 24 * time.Hour

	return passwordAge > maxAge
}

// IsActive returns whether the user account is active
func (u *User) IsActiveAccount() bool {
	return u.Active && u.Status == UserStatusActive && u.DeletedAt == nil
}

// IsSuperAdmin returns whether the user is a super admin
func (u *User) IsSuperAdmin() bool {
	return u.Role == RoleSuperAdmin || u.OrgSuperAdmin
}

// IsOrgAdmin returns whether the user is an organization admin
func (u *User) IsOrgAdmin() bool {
	return u.Role == RoleAdmin
}

// IsManager returns whether the user is a manager
func (u *User) IsManager() bool {
	return u.Role == RoleManager
}

// SoftDelete marks the user as deleted
func (u *User) SoftDelete(ctx orm.DB) error {
	now := time.Now()
	u.DeletedAt = &now
	u.Status = UserStatusInactive
	u.Active = false

	_, err := ctx.Model(u).
		Set("deleted_at = ?", now).
		Set("status = ?", UserStatusInactive).
		Set("active = ?", false).
		Set("updated_at = ?", now).
		Where("id = ?", u.ID).
		Update()

	return err
}

// GenerateAPIKey creates a new API key for the user
func (u *User) GenerateAPIKey(ctx orm.DB, expiryDays int) (string, error) {
	// Generate a UUID as the API key
	apiKey := uuid.New().String()

	// Set expiry date
	now := time.Now()
	expiryDate := now.AddDate(0, 0, expiryDays)

	// Update the user record
	u.APIKey = apiKey
	u.APIKeyExpiry = expiryDate

	_, err := ctx.Model(u).
		Set("api_key = ?", apiKey).
		Set("api_key_expiry = ?", expiryDate).
		Set("updated_at = ?", now).
		Where("id = ?", u.ID).
		Update()

	if err != nil {
		return "", err
	}

	return apiKey, nil
}

// RevokeAPIKey revokes the user's API key
func (u *User) RevokeAPIKey(ctx orm.DB) error {
	now := time.Now()

	u.APIKey = ""
	u.APIKeyExpiry = time.Time{}

	_, err := ctx.Model(u).
		Set("api_key = NULL").
		Set("api_key_expiry = NULL").
		Set("updated_at = ?", now).
		Where("id = ?", u.ID).
		Update()

	return err
}

// HasValidAPIKey checks if the user has a valid API key
func (u *User) HasValidAPIKey() bool {
	return u.APIKey != "" && u.APIKeyExpiry.After(time.Now())
}

// CanManageOrganization checks if the user can manage the specified organization
func (u *User) CanManageOrganization(orgID uuid.UUID) bool {
	// Super admins can manage any organization
	if u.IsSuperAdmin() {
		// If ManagedOrgIDs is specified, check if the org is in the list
		if len(u.ManagedOrgIDs) > 0 {
			for _, id := range u.ManagedOrgIDs {
				if id == orgID {
					return true
				}
			}
			return false
		}
		// If no specific orgs are specified, they can manage any org
		return true
	}

	// Organization admins can only manage their own organization
	if u.IsOrgAdmin() && u.OrganizationID == orgID {
		return true
	}

	return false
}
