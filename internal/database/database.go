package database

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"os"

	"gobackend/internal/config"
	"gobackend/internal/models"

	"github.com/go-pg/pg/v10"
	"github.com/go-pg/pg/v10/orm"
)

// DB is a wrapper around pg.DB
type DB struct {
	*pg.DB
	IsMock bool
}

// New creates a new database connection
func New(cfg *config.Config) (*DB, error) {
	// Check if we should use mock database
	if os.Getenv("USE_MOCK_DB") == "true" {
		log.Println("Using mock database")
		return NewMockDB(), nil
	}

	dbCfg := &pg.Options{
		Addr:     fmt.Sprintf("%s:%d", cfg.Database.Host, cfg.Database.Port),
		User:     cfg.Database.User,
		Password: cfg.Database.Password,
		Database: cfg.Database.Name,
		PoolSize: cfg.Database.MaxConnections,
		TLSConfig: nil,
	}

	if cfg.Database.SSLMode == "require" || cfg.Database.SSLMode == "verify-ca" || cfg.Database.SSLMode == "verify-full" {
        		dbCfg.TLSConfig = &tls.Config{
        			InsecureSkipVerify: cfg.Database.SSLMode == "require", // For 'require', skip verification. Needs CA for others.
        }
        	log.Printf("TLS enabled for database connection (SSLMode: %s)", cfg.Database.SSLMode)
        } else {
        	 log.Printf("TLS disabled for database connection (SSLMode: %s)", cfg.Database.SSLMode)
        	}

        log.Printf("Connecting to database at %s with user %s", dbCfg.Addr, dbCfg.User)

	db := pg.Connect(dbCfg)

	// Ping the database to test the connection
	ctx := context.Background()
	if err := db.Ping(ctx); err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Set up a query hook for logging queries in debug mode
	if cfg.App.Debug {
		db.AddQueryHook(dbLogger{})
	}

	return &DB{DB: db, IsMock: false}, nil
}

// NewMockDB creates a new mock database for testing
func NewMockDB() *DB {
	log.Println("Mock database initialized")
	return &DB{DB: nil, IsMock: true}
}

// CreateSchema creates the database schema for the models
func (db *DB) CreateSchema() error {
	// Skip schema creation for mock database
	if db.IsMock {
		log.Println("Skipping schema creation for mock database")
		return nil
	}

	// Add models here to automatically create tables
	models := []interface{}{
		(*models.Tenant)(nil),
		(*models.Organization)(nil),
//		(*models.Team)(nil),
//		(*models.TeamMember)(nil),
		(*models.User)(nil),
		(*models.AuditLog)(nil),
	}

	for _, model := range models {
		err := db.Model(model).CreateTable(&orm.CreateTableOptions{
			IfNotExists: true,
			Temp:        false,
		})
		if err != nil {
			return fmt.Errorf("failed to create table for model %T: %w", model, err)
		}
	}

	// Log schema creation success
	log.Println("Database schema created successfully")
	return nil
}

// Close closes the database connection
func (db *DB) Close() {
	if db.IsMock {
		return
	}
	if err := db.DB.Close(); err != nil {
		log.Printf("Error closing database connection: %v", err)
	}
}

// dbLogger implements the pg.QueryHook interface for query logging
type dbLogger struct{}

// BeforeQuery logs a query before it's executed
func (d dbLogger) BeforeQuery(ctx context.Context, q *pg.QueryEvent) (context.Context, error) {
	return ctx, nil
}

// AfterQuery logs a query after it's executed
func (d dbLogger) AfterQuery(ctx context.Context, q *pg.QueryEvent) error {
	query, err := q.FormattedQuery()
	if err != nil {
		return err
	}

	log.Printf("SQL: %s", query)
	return nil
}

// WithTransaction executes a function within a transaction
func (db *DB) WithTransaction(fn func(*pg.Tx) error) error {
	if db.IsMock {
		// For mock DB, just execute the function without a transaction
		// Mock an empty transaction
		return nil
	}
	return db.RunInTransaction(context.Background(), func(tx *pg.Tx) error {
		return fn(tx)
	})
}

// SafeExec executes a query with automatic retry on connection failures
func (db *DB) SafeExec(ctx context.Context, query string, params ...interface{}) (pg.Result, error) {
	if db.IsMock {
		// Return a mock result
		return nil, nil
	}

	var result pg.Result
	var err error

	// Retry up to 3 times for transient errors
	for i := 0; i < 3; i++ {
		result, err = db.ExecContext(ctx, query, params...)
		if err == nil || !isRetryableError(err) {
			break
		}
		log.Printf("Retrying database query after error: %v", err)
	}

	return result, err
}

// isRetryableError determines if an error is retryable
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// Check for connection errors, timeout errors, etc.
	errStr := err.Error()
	return pg.ErrTxDone.Error() == errStr ||
		errStr == "stmt is closed" ||
		errStr == "pg: connection is closed" ||
		errStr == "pg: database is closed" ||
		errStr == "context deadline exceeded" ||
		errStr == "i/o timeout"
}
