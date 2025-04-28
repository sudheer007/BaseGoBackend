package models

import (
	"time"

	"github.com/go-pg/pg/v10/orm"
	"github.com/google/uuid"
)

// Permission represents a specific permission in the system
type Permission struct {
	ID          uuid.UUID `pg:"id,type:uuid,pk"`
	Resource    string    `pg:"resource,notnull"` // e.g., "organization", "team", "user"
	Action      string    `pg:"action,notnull"`   // e.g., "create", "read", "update", "delete"
	Description string    `pg:"description"`
	CreatedAt   time.Time `pg:"created_at,notnull,default:now()"`
	UpdatedAt   time.Time `pg:"updated_at,notnull,default:now()"`
}

// BeforeInsert hook is called before inserting a new permission
func (p *Permission) BeforeInsert(ctx orm.DB) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	p.CreatedAt = time.Now()
	p.UpdatedAt = time.Now()
	return nil
}

// BeforeUpdate hook is called before updating a permission
func (p *Permission) BeforeUpdate(ctx orm.DB) error {
	p.UpdatedAt = time.Now()
	return nil
}

// TableName returns the name of the table for this model
func (p *Permission) TableName() string {
	return "permissions"
}

// RolePermission represents the many-to-many relationship between roles and permissions
type RolePermission struct {
	RoleID       string    `pg:"role,pk"`          // e.g., "super_admin", "admin", "manager", "user"
	PermissionID uuid.UUID `pg:"permission_id,pk"` // Reference to Permission.ID
	CreatedAt    time.Time `pg:"created_at,notnull,default:now()"`
}

// TableName returns the name of the table for this model
func (rp *RolePermission) TableName() string {
	return "role_permissions"
}

// ResourceScope represents the scope of a permission for a user (organization, team, user level)
type ResourceScope struct {
	ID           uuid.UUID   `pg:"id,type:uuid,pk"`
	UserID       uuid.UUID   `pg:"user_id,type:uuid,notnull"`
	ResourceType string      `pg:"resource_type,notnull"` // "organization", "team", "user"
	ResourceID   uuid.UUID   `pg:"resource_id,type:uuid,notnull"`
	AccessLevel  AccessLevel `pg:"access_level,type:text,notnull"`
	CreatedAt    time.Time   `pg:"created_at,notnull,default:now()"`
	UpdatedAt    time.Time   `pg:"updated_at,notnull,default:now()"`

	// Relations
	User *User `pg:"rel:has-one,fk:user_id"`
}

// AccessLevel defines the level of access a user has to a resource
type AccessLevel string

// Access levels
const (
	AccessLevelOwner     AccessLevel = "owner"     // Full control
	AccessLevelAdmin     AccessLevel = "admin"     // Administrative access
	AccessLevelManage    AccessLevel = "manage"    // Can manage but not delete
	AccessLevelModify    AccessLevel = "modify"    // Can modify but not manage users
	AccessLevelReadWrite AccessLevel = "readwrite" // Can read and write
	AccessLevelReadOnly  AccessLevel = "readonly"  // Can only read
)

// BeforeInsert hook is called before inserting a new resource scope
func (rs *ResourceScope) BeforeInsert(ctx orm.DB) error {
	if rs.ID == uuid.Nil {
		rs.ID = uuid.New()
	}
	rs.CreatedAt = time.Now()
	rs.UpdatedAt = time.Now()
	return nil
}

// BeforeUpdate hook is called before updating a resource scope
func (rs *ResourceScope) BeforeUpdate(ctx orm.DB) error {
	rs.UpdatedAt = time.Now()
	return nil
}

// TableName returns the name of the table for this model
func (rs *ResourceScope) TableName() string {
	return "resource_scopes"
}
