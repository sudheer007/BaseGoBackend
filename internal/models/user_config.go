package models

import (
	"time"

	"github.com/google/uuid"
)

// UserConfig represents a user's configuration
type UserConfig struct {
	ID        uuid.UUID    `pg:"id,type:uuid,pk"`
	UserID    uuid.UUID    `pg:"user_id,type:uuid,notnull,unique"`
	Settings  UserSettings `pg:"settings,type:jsonb"`
	CreatedAt time.Time    `pg:"created_at,notnull,default:now()"`
	UpdatedAt time.Time    `pg:"updated_at,notnull,default:now()"`
}

// UserSettings represents the settings container
type UserSettings struct {
	UserPreferences UserPreferences `json:"user_preferences"`
}

// UserPreferences represents user preferences
type UserPreferences struct {
	AccountSettings      AccountSettings      `json:"account settings"`
	AIAssistantSettings  AIAssistantSettings  `json:"ai_assistant_settings"`
	NotificationSettings NotificationSettings `json:"notification_settings"`
}

// AccountSettings represents user account settings
type AccountSettings struct {
	Email          string `json:"email"`
	FirstName      string `json:"first_name"`
	LastName       string `json:"last_name"`
	DisplayName    string `json:"display_name"`
	TimeZone       string `json:"time_zone"`
	ProfilePicture string `json:"profile_picture"`
}

// AIAssistantSettings represents AI assistant settings
type AIAssistantSettings struct {
	EnableAIAssistant bool   `json:"enable_ai_assistant"`
	AISuggestions     bool   `json:"ai_suggestions"`
	AIModel           string `json:"ai_model"`
}

// NotificationSettings represents notification settings
type NotificationSettings struct {
	EmailNotifications bool `json:"email_notifications"`
	PushNotifications  bool `json:"push_notifications"`
	WeeklyDigest       bool `json:"weekly_digest"`
}

// TableName returns the name of the table for this model
func (c *UserConfig) TableName() string {
	return "user_configs"
}

// BeforeUpdate hook is called before updating a user config
func (c *UserConfig) BeforeUpdate() error {
	c.UpdatedAt = time.Now()
	return nil
}
