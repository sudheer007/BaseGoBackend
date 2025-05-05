package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gobackend/internal/models"

	"github.com/go-pg/pg/v10"
	"github.com/google/uuid"
)

// UserConfigService provides functionality for managing user configurations
type UserConfigService struct {
	db *pg.DB
}

// NewUserConfigService creates a new user config service
func NewUserConfigService(db *pg.DB) *UserConfigService {
	return &UserConfigService{
		db: db,
	}
}

// UpdateUserConfig updates a user's configuration
func (s *UserConfigService) UpdateUserConfig(ctx context.Context, userIDStr string, settings models.UserSettings) (*models.UserConfig, error) {
	// Parse user ID
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID format: %w", err)
	}

	// Verify user exists
	user := new(models.User)
	err = s.db.Model(user).Where("id = ?", userID).Select()
	if err != nil {
		if errors.Is(err, pg.ErrNoRows) {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("database error: %w", err)
	}

	// Check if user config exists
	config := new(models.UserConfig)
	err = s.db.Model(config).Where("user_id = ?", userID).Select()

	if err != nil {
		if errors.Is(err, pg.ErrNoRows) {
			// Config doesn't exist, create a new one
			config = &models.UserConfig{
				ID:        uuid.New(),
				UserID:    userID,
				Settings:  settings,
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}

			_, err = s.db.Model(config).Insert()
			if err != nil {
				return nil, fmt.Errorf("failed to create user config: %w", err)
			}
		} else {
			return nil, fmt.Errorf("database error: %w", err)
		}
	} else {
		// Config exists, update it
		config.Settings = settings
		config.UpdatedAt = time.Now()

		_, err = s.db.Model(config).
			Set("settings = ?", settings).
			Set("updated_at = ?", time.Now()).
			Where("id = ?", config.ID).
			Update()

		if err != nil {
			return nil, fmt.Errorf("failed to update user config: %w", err)
		}
	}

	// Apply email and name changes to user record if they were updated
	accountSettings := settings.UserPreferences.AccountSettings
	if accountSettings.Email != "" && accountSettings.Email != user.Email {
		user.Email = accountSettings.Email
	}

	if accountSettings.FirstName != "" && accountSettings.FirstName != user.FirstName {
		user.FirstName = accountSettings.FirstName
	}

	if accountSettings.LastName != "" && accountSettings.LastName != user.LastName {
		user.LastName = accountSettings.LastName
	}

	// Update user record if needed
	if user.Email != "" || user.FirstName != "" || user.LastName != "" {
		user.UpdatedAt = time.Now()
		_, err = s.db.Model(user).
			Column("email", "first_name", "last_name", "updated_at").
			Where("id = ?", userID).
			Update()

		if err != nil {
			return nil, fmt.Errorf("failed to update user profile: %w", err)
		}
	}

	return config, nil
}
