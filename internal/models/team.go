package models

import (
	"time"

	"github.com/go-pg/pg/v10/orm"
	"github.com/google/uuid"
)

// TeamStatus represents the status of a team
type TeamStatus string

// Available team statuses
const (
	TeamStatusActive   TeamStatus = "active"
	TeamStatusInactive TeamStatus = "inactive"
	TeamStatusArchived TeamStatus = "archived"
)

// Team represents a team within an organization
type Team struct {
	ID             uuid.UUID  `pg:"id,type:uuid,pk"`
	Name           string     `pg:"name,notnull"`
	Description    string     `pg:"description"`
	OrganizationID uuid.UUID  `pg:"organization_id,type:uuid,notnull"`
	Status         TeamStatus `pg:"status,type:text,notnull,default:'active'"`
	CreatedBy      uuid.UUID  `pg:"created_by,type:uuid,notnull"`
	CreatedAt      time.Time  `pg:"created_at,notnull,default:now()"`
	UpdatedAt      time.Time  `pg:"updated_at,notnull,default:now()"`
	DeletedAt      *time.Time `pg:"deleted_at"`

	// Relations
	Organization *Organization `pg:"rel:has-one,fk:organization_id"`
	Creator      *User         `pg:"rel:has-one,fk:created_by"`
	Members      []*User       `pg:"many2many:team_members"`
}

// TeamMember represents the many-to-many relationship between teams and users
type TeamMember struct {
	TeamID    uuid.UUID `pg:"team_id,type:uuid,pk"`
	UserID    uuid.UUID `pg:"user_id,type:uuid,pk"`
	Role      string    `pg:"role,notnull"` // member, lead, admin
	CreatedAt time.Time `pg:"created_at,notnull,default:now()"`
}

// BeforeInsert hook is called before inserting a new team
func (t *Team) BeforeInsert(ctx orm.DB) error {
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	t.CreatedAt = time.Now()
	t.UpdatedAt = time.Now()
	return nil
}

// BeforeUpdate hook is called before updating a team
func (t *Team) BeforeUpdate(ctx orm.DB) error {
	t.UpdatedAt = time.Now()
	return nil
}

// TableName returns the name of the table for this model
func (t *Team) TableName() string {
	return "teams"
}

// TableName returns the name of the table for TeamMember model
func (tm *TeamMember) TableName() string {
	return "team_members"
}

// IsActive returns whether the team is active
func (t *Team) IsActive() bool {
	return t.Status == TeamStatusActive
}

// GetMembersCount returns the number of members in the team
func (t *Team) GetMembersCount(ctx orm.DB) (int, error) {
	count, err := ctx.Model((*TeamMember)(nil)).
		Where("team_id = ?", t.ID).
		Count()
	return count, err
}

// SoftDelete marks the team as deleted
func (t *Team) SoftDelete(ctx orm.DB) error {
	now := time.Now()
	t.DeletedAt = &now
	t.Status = TeamStatusInactive
	_, err := ctx.Model(t).
		Set("deleted_at = ?", now).
		Set("status = ?", TeamStatusInactive).
		Set("updated_at = ?", now).
		Where("id = ?", t.ID).
		Update()
	return err
}

// AddMember adds a user to the team
func (t *Team) AddMember(ctx orm.DB, userID uuid.UUID, role string) error {
	member := &TeamMember{
		TeamID: t.ID,
		UserID: userID,
		Role:   role,
	}
	_, err := ctx.Model(member).Insert()
	return err
}

// RemoveMember removes a user from the team
func (t *Team) RemoveMember(ctx orm.DB, userID uuid.UUID) error {
	_, err := ctx.Model((*TeamMember)(nil)).
		Where("team_id = ? AND user_id = ?", t.ID, userID).
		Delete()
	return err
}

// HasMember checks if a user is a member of the team
func (t *Team) HasMember(ctx orm.DB, userID uuid.UUID) (bool, error) {
	count, err := ctx.Model((*TeamMember)(nil)).
		Where("team_id = ? AND user_id = ?", t.ID, userID).
		Count()
	return count > 0, err
}

// GetMemberRole returns the role of a user in the team
func (t *Team) GetMemberRole(ctx orm.DB, userID uuid.UUID) (string, error) {
	var member TeamMember
	err := ctx.Model(&member).
		Where("team_id = ? AND user_id = ?", t.ID, userID).
		Select()
	return member.Role, err
}
