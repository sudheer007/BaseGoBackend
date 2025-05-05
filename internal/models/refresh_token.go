package models

import (
	"time"

	"github.com/google/uuid"
)

// RefreshToken represents a refresh token stored in the database
type RefreshToken struct {
	ID        uuid.UUID `pg:"id,type:uuid,pk"`
	UserID    uuid.UUID `pg:"user_id,type:uuid,notnull"`
	TokenID   string    `pg:"token_id,notnull"`
	ExpiresAt time.Time `pg:"expires_at,notnull"`
	CreatedAt time.Time `pg:"created_at,notnull,default:now()"`
	Revoked   bool      `pg:"revoked,notnull,default:false"`
	IPAddress string    `pg:"ip_address"`
	UserAgent string    `pg:"user_agent"`
}

// TableName returns the name of the table for this model
func (t *RefreshToken) TableName() string {
	return "refresh_tokens"
}
