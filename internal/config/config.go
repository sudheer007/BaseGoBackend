package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"gobackend/internal/observability"
	"gobackend/internal/security"
	"gobackend/internal/services/thirdparty/openrouter"

	"github.com/joho/godotenv"
)

const (
	EnvLocal       = "local"
	EnvDevelopment = "development"
	EnvProduction  = "production"
)

// Config holds all configuration for the application
type Config struct {
	App         AppConfig
	Database    DatabaseConfig
	Redis       RedisConfig
	JWT         JWTConfig
	Security    SecurityConfig
	RateLimit   RateLimitConfig
	CORS        CORSConfig
	Audit       AuditConfig
	ThirdParty  ThirdPartyConfig
	Jobs        JobsConfig
	Metrics     *observability.Config
	Logging     *observability.LoggingConfig
	Payment     PaymentConfig
	Environment string `env:"ENVIRONMENT" envDefault:"development"`
	Debug       bool   `env:"DEBUG" envDefault:"true"`
	LogLevel    string `env:"LOG_LEVEL" envDefault:"debug"`

	Server struct {
		Port int `env:"PORT" envDefault:"8080"`
	}
}

// AppConfig holds application-level configuration
type AppConfig struct {
	Name     string
	Env      string // Should be local, development, or production
	Port     int
	Debug    bool // Automatically set based on Env
	Secret   string
	LogLevel string // Automatically set based on Env
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
	Host     string `env:"REDIS_HOST" envDefault:"localhost"`
	Port     int    `env:"REDIS_PORT" envDefault:"6379"`
	Password string `env:"REDIS_PASSWORD" envDefault:""`
	DB       int    `env:"REDIS_DB" envDefault:"0"`
	Enabled  bool   `env:"REDIS_ENABLED" envDefault:"true"`
}

// JWTConfig holds JWT configuration
type JWTConfig struct {
	Secret         string        `env:"JWT_SECRET" envDefault:"insecure-jwt-secret"`
	ExpiryDuration time.Duration `env:"JWT_EXPIRY" envDefault:"24h"`
	RefreshExpiry  time.Duration `env:"JWT_REFRESH_EXPIRY" envDefault:"72h"`
}

// SecurityConfig holds security-related configuration
type SecurityConfig struct {
	PasswordHashCost  int
	PasswordMinLength int
	EncryptionKey     string
	EncryptionSalt    string
	FieldEncryption   bool
	JWT               JWTConfig
}

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	RequestsPerSecond float64 `env:"RATE_LIMIT_RPS" envDefault:"10"`
	Burst             int     `env:"RATE_LIMIT_BURST" envDefault:"20"`
	ExpireMinutes     int     `env:"RATE_LIMIT_EXPIRE" envDefault:"1"`
	Enabled           bool    `env:"RATE_LIMIT_ENABLED" envDefault:"true"`
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

// JobsConfig holds background job configuration
type JobsConfig struct {
	Workers             int
	PollIntervalSeconds int
	Enabled             bool
}

// PaymentConfig holds payment providers configuration
type PaymentConfig struct {
	Razorpay RazorpayConfig
}

// RazorpayConfig holds Razorpay configuration
type RazorpayConfig struct {
	KeyID         string
	KeySecret     string
	WebhookSecret string
	Currency      string
	Enabled       bool
}

// Load loads configuration from environment variables
func Load() (*Config, error) {
	// Attempt to load .env file - useful for local dev, ignored in production if vars are set
	_ = godotenv.Load()

	appEnv := getEnv("APP_ENV", EnvLocal) // Default to local if not set
	debug := appEnv != EnvProduction
	logLevel := "info" // Default log level
	if debug {
		logLevel = "debug"
	}

	return &Config{
		App: AppConfig{
			Name:     getEnv("APP_NAME", "secure-api"),
			Env:      appEnv,
			Port:     getEnvAsInt("APP_PORT", 8080),
			Debug:    debug,
			Secret:   getEnv("APP_SECRET", "insecure-default-secret"),
			LogLevel: getEnv("APP_LOG_LEVEL", logLevel),
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
			Enabled:  getEnvAsBool("REDIS_ENABLED", true),
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
			JWT: JWTConfig{
				Secret:         getEnv("JWT_SECRET", "insecure-jwt-secret"),
				ExpiryDuration: getEnvAsDuration("JWT_EXPIRY", 24*time.Hour),
				RefreshExpiry:  getEnvAsDuration("JWT_REFRESH_EXPIRY", 72*time.Hour),
			},
		},
		RateLimit: RateLimitConfig{
			RequestsPerSecond: getEnvAsFloat64("RATE_LIMIT_RPS", 10),
			Burst:             getEnvAsInt("RATE_LIMIT_BURST", 20),
			ExpireMinutes:     getEnvAsInt("RATE_LIMIT_EXPIRE", 1),
			Enabled:           getEnvAsBool("RATE_LIMIT_ENABLED", true),
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
		ThirdParty: ThirdPartyConfig{
			OpenRouter: OpenRouterConfig{
				ApiKey:  getEnv("OPENROUTER_API_KEY", ""),
				BaseURL: getEnv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
				Enabled: getEnvAsBool("OPENROUTER_ENABLED", false),
			},
		},
		Jobs: JobsConfig{
			Workers:             getEnvAsInt("JOBS_WORKERS", 5),
			PollIntervalSeconds: getEnvAsInt("JOBS_POLL_INTERVAL", 5),
			Enabled:             getEnvAsBool("JOBS_ENABLED", true),
		},
		Metrics: &observability.Config{
			Enabled:          getEnvAsBool("METRICS_ENABLED", true),
			MetricsNamespace: getEnv("METRICS_NAMESPACE", "gobackend"),
		},
		Logging: &observability.LoggingConfig{
			Level:      observability.LogLevel(getEnv("LOG_LEVEL", "info")),
			JSONFormat: getEnvAsBool("LOG_JSON", true),
			OutputPath: getEnv("LOG_FILE", ""),
		},
		Payment: PaymentConfig{
			Razorpay: RazorpayConfig{
				KeyID:         getEnv("RAZORPAY_KEY_ID", ""),
				KeySecret:     getEnv("RAZORPAY_KEY_SECRET", ""),
				WebhookSecret: getEnv("RAZORPAY_WEBHOOK_SECRET", ""),
				Currency:      getEnv("RAZORPAY_CURRENCY", "INR"),
				Enabled:       getEnvAsBool("RAZORPAY_ENABLED", false),
			},
		},
		Environment: getEnv("ENVIRONMENT", EnvDevelopment),
		Debug:       getEnvAsBool("DEBUG", true),
		LogLevel:    getEnv("LOG_LEVEL", "debug"),
		Server: struct {
			Port int `env:"PORT" envDefault:"8080"`
		}{
			Port: getEnvAsInt("PORT", 8080),
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

func getEnvAsFloat64(key string, defaultValue float64) float64 {
	valueStr := getEnv(key, "")
	if value, err := strconv.ParseFloat(valueStr, 64); err == nil {
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

// ThirdPartyConfig holds third-party service configurations
type ThirdPartyConfig struct {
	OpenRouter OpenRouterConfig
}

// OpenRouterConfig holds OpenRouter API configuration
type OpenRouterConfig struct {
	ApiKey  string `env:"OPENROUTER_API_KEY" envDefault:""`
	BaseURL string `env:"OPENROUTER_BASE_URL" envDefault:"https://openrouter.ai/api/v1"`
	Enabled bool   `env:"OPENROUTER_ENABLED" envDefault:"false"`
}

func (c OpenRouterConfig) ToServiceConfig() openrouter.Config {
	return openrouter.Config{
		APIKey:           c.ApiKey,
		BaseURL:          c.BaseURL,
		TimeoutSeconds:   30,
		RetryAttempts:    3,
		RetryWaitSeconds: 1,
		AppName:          "GoBackend API",
		AppURL:           "",
	}
}

func validateConfig(cfg *Config) error {
	if cfg.Security.EncryptionKey == "" {
		return errors.New("encryption key is required")
	}
	if cfg.Security.EncryptionSalt == "" {
		return errors.New("encryption salt is required")
	}
	return nil
}
