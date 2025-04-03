package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"gobackend/internal/security"

	"github.com/joho/godotenv"
)

// Config holds all configuration for the application
type Config struct {
	App       AppConfig
	Database  DatabaseConfig
	Redis     RedisConfig
	JWT       JWTConfig
	Security  SecurityConfig
	RateLimit RateLimitConfig
	CORS      CORSConfig
	Audit     AuditConfig
}

// AppConfig holds application-level configuration
type AppConfig struct {
	Name     string
	Env      string
	Port     int
	Debug    bool
	Secret   string
	LogLevel string
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	Host            string
	Port            int
	User            string
	Password        string
	Name            string
	SSLMode         string
	Timeout         int
	MaxConnections  int
	IdleConnections int
}

// RedisConfig holds Redis configuration
type RedisConfig struct {
	Host     string
	Port     int
	Password string
	DB       int
}

// JWTConfig holds JWT configuration
type JWTConfig struct {
	Secret         string
	ExpiryDuration time.Duration
	RefreshExpiry  time.Duration
}

// SecurityConfig holds security-related configuration
type SecurityConfig struct {
	PasswordHashCost  int
	PasswordMinLength int
	EncryptionKey     string
	EncryptionSalt    string
	FieldEncryption   bool
}

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	Requests int
	Duration time.Duration
}

// CORSConfig holds CORS configuration
type CORSConfig struct {
	AllowedOrigins   string
	AllowedMethods   string
	AllowedHeaders   string
	ExposedHeaders   string
	AllowCredentials bool
	MaxAge           time.Duration
}

// AuditConfig holds audit logging configuration
type AuditConfig struct {
	Enabled       bool
	RetentionDays int
}

// Load loads configuration from environment variables
func Load() (*Config, error) {
	// Load .env file if it exists
	godotenv.Load()

	return &Config{
		App: AppConfig{
			Name:     getEnv("APP_NAME", "secure-api"),
			Env:      getEnv("APP_ENV", "development"),
			Port:     getEnvAsInt("APP_PORT", 8080),
			Debug:    getEnvAsBool("APP_DEBUG", true),
			Secret:   getEnv("APP_SECRET", "insecure-default-secret"),
			LogLevel: getEnv("APP_LOG_LEVEL", "info"),
		},
		Database: DatabaseConfig{
			Host:            getEnv("DB_HOST", "localhost"),
			Port:            getEnvAsInt("DB_PORT", 5432),
			User:            getEnv("DB_USER", "postgres"),
			Password:        getEnv("DB_PASS", "postgres"),
			Name:            getEnv("DB_NAME", "secureapi"),
			SSLMode:         getEnv("DB_SSL_MODE", "disable"),
			Timeout:         getEnvAsInt("DB_TIMEOUT", 30),
			MaxConnections:  getEnvAsInt("DB_MAX_CONNECTIONS", 100),
			IdleConnections: getEnvAsInt("DB_IDLE_CONNECTIONS", 10),
		},
		Redis: RedisConfig{
			Host:     getEnv("REDIS_HOST", "localhost"),
			Port:     getEnvAsInt("REDIS_PORT", 6379),
			Password: getEnv("REDIS_PASS", ""),
			DB:       getEnvAsInt("REDIS_DB", 0),
		},
		JWT: JWTConfig{
			Secret:         getEnv("JWT_SECRET", "insecure-jwt-secret"),
			ExpiryDuration: getEnvAsDuration("JWT_EXPIRY", 24*time.Hour),
			RefreshExpiry:  getEnvAsDuration("JWT_REFRESH_EXPIRY", 72*time.Hour),
		},
		Security: SecurityConfig{
			PasswordHashCost:  getEnvAsInt("PASSWORD_HASH_COST", 12),
			PasswordMinLength: getEnvAsInt("PASSWORD_MIN_LENGTH", 12),
			EncryptionKey:     getEnv("PASSWORD_ENCRYPTION_KEY", ""),
			EncryptionSalt:    getEnv("PASSWORD_ENCRYPTION_SALT", ""),
			FieldEncryption:   getEnvAsBool("PASSWORD_FIELD_ENCRYPTION", false),
		},
		RateLimit: RateLimitConfig{
			Requests: getEnvAsInt("RATE_LIMIT_REQUESTS", 100),
			Duration: getEnvAsDuration("RATE_LIMIT_DURATION", time.Minute),
		},
		CORS: CORSConfig{
			AllowedOrigins:   getEnv("CORS_ALLOWED_ORIGINS", "*"),
			AllowedMethods:   getEnv("CORS_ALLOWED_METHODS", "GET,POST,PUT,DELETE,OPTIONS"),
			AllowedHeaders:   getEnv("CORS_ALLOWED_HEADERS", "Authorization,Content-Type"),
			ExposedHeaders:   getEnv("CORS_EXPOSED_HEADERS", "Content-Length"),
			AllowCredentials: getEnvAsBool("CORS_ALLOW_CREDENTIALS", true),
			MaxAge:           getEnvAsDuration("CORS_MAX_AGE", 12*time.Hour),
		},
		Audit: AuditConfig{
			Enabled:       getEnvAsBool("AUDIT_LOG_ENABLED", true),
			RetentionDays: getEnvAsInt("AUDIT_LOG_RETENTION_DAYS", 90),
		},
	}, nil
}

// Helper functions to get environment variables with default values
func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	valueStr := getEnv(key, "")
	if value, err := strconv.Atoi(valueStr); err == nil {
		return value
	}
	return defaultValue
}

func getEnvAsBool(key string, defaultValue bool) bool {
	valueStr := getEnv(key, "")
	if value, err := strconv.ParseBool(valueStr); err == nil {
		return value
	}
	return defaultValue
}

func getEnvAsDuration(key string, defaultValue time.Duration) time.Duration {
	valueStr := getEnv(key, "")
	if value, err := time.ParseDuration(valueStr); err == nil {
		return value
	}
	return defaultValue
}

// GetDSN returns the database connection string
func (c *DatabaseConfig) GetDSN() string {
	return fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=%s&timeout=%ds",
		c.User,
		c.Password,
		c.Host,
		c.Port,
		c.Name,
		c.SSLMode,
		c.Timeout,
	)
}

// GetRedisAddr returns the Redis address as host:port
func (c *RedisConfig) GetRedisAddr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// BuildEncryptionService builds an encryption service from the configuration
func (c *SecurityConfig) BuildEncryptionService() (*security.EncryptionService, error) {
	// If encryption is not configured, return nil
	if !c.FieldEncryption || c.EncryptionKey == "" || c.EncryptionSalt == "" {
		return nil, nil
	}

	// Create and return the encryption service
	return security.NewEncryptionService(c.EncryptionKey, c.EncryptionSalt)
}
