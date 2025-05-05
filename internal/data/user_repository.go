package data

import (
	"context"
	"errors"
	"time"

	"gobackend/internal/models"

	"github.com/go-pg/pg/v10"
	"github.com/google/uuid"
)

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrEmailAlreadyExists = errors.New("email already exists")
)

// UserRepository handles database operations for users
type UserRepository struct {
	db *pg.DB
}

// NewUserRepository creates a new user repository
func NewUserRepository(db *pg.DB) *UserRepository {
	return &UserRepository{db: db}
}

// AddUser creates a new user in the database
func (r *UserRepository) AddUser(ctx context.Context, user *models.User) error {
	// Start a transaction
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Check if email already exists
	exists, err := tx.Model((*models.User)(nil)).
		Where("email = ?", user.Email).
		Exists()
	if err != nil {
		return err
	}
	if exists {
		return ErrEmailAlreadyExists
	}

	// Make sure user ID is set
	if user.ID == uuid.Nil {
		user.ID = uuid.New()
	}

	// Set default values if not provided
	if user.Status == "" {
		user.Status = models.UserStatusActive
	}
	if user.Role == "" {
		user.Role = models.RoleUser
	}
	if user.CreatedAt.IsZero() {
		user.CreatedAt = time.Now()
	}
	if user.UpdatedAt.IsZero() {
		user.UpdatedAt = time.Now()
	}

	// Insert the user
	_, err = tx.Model(user).Insert()
	if err != nil {
		return err
	}

	// Commit the transaction
	return tx.Commit()
}

// GetUserByID retrieves a user by ID
func (r *UserRepository) GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	user := new(models.User)
	err := r.db.Model(user).Where("id = ?", id).Select()
	if err != nil {
		if errors.Is(err, pg.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return user, nil
}

// GetUserByEmail retrieves a user by email
func (r *UserRepository) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	user := new(models.User)
	err := r.db.Model(user).Where("email = ?", email).Select()
	if err != nil {
		if errors.Is(err, pg.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return user, nil
}
