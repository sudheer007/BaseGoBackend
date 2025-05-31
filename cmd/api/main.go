package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gobackend/docs"
	"gobackend/internal/api"
	"gobackend/internal/audit"
	"gobackend/internal/auth"
	"gobackend/internal/config"
	"gobackend/internal/jobs"
	"gobackend/internal/observability"
	"gobackend/internal/services"
	"gobackend/razorpay"

	"crypto/tls"

	"github.com/go-pg/pg/v10"
	"github.com/go-redis/redis/v8"
	_ "github.com/swaggo/files"       // swagger files
	_ "github.com/swaggo/gin-swagger" // swagger generator
)

// @title           GoBackend API
// @version         1.0
// @description     A secure Go backend API with Swagger.
// @termsOfService  http://swagger.io/terms/

// @contact.name   API Support
// @contact.url    http://www.example.com/support
// @contact.email  support@example.com

// @license.name  Apache 2.0
// @license.url   http://www.apache.org/licenses/LICENSE-2.0.html

// @host      localhost:8080
// @BasePath  /

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token.

// NoOpQueue is a simple implementation of Queue interface for testing or when queue is disabled
type NoOpQueue struct{}

func (q *NoOpQueue) Enqueue(ctx context.Context, job *jobs.Job) error {
	return nil
}

func (q *NoOpQueue) EnqueueBatch(ctx context.Context, jobs []*jobs.Job) error {
	return nil
}

func (q *NoOpQueue) Dequeue(ctx context.Context) (*jobs.Job, error) {
	return nil, jobs.ErrNoJobAvailable
}

func (q *NoOpQueue) Complete(ctx context.Context, job *jobs.Job) error {
	return nil
}

func (q *NoOpQueue) Failed(ctx context.Context, job *jobs.Job, err error) error {
	return nil
}

func (q *NoOpQueue) Retry(ctx context.Context, job *jobs.Job, err error) error {
	return nil
}

func (q *NoOpQueue) Size(ctx context.Context) (int, error) {
	return 0, nil
}

func main() {
	// Initialize Swagger docs
	docs.SwaggerInfo.Title = "GoBackend API"
	docs.SwaggerInfo.Description = "A secure Go backend API with Organization CRUD operations"
	docs.SwaggerInfo.Version = "1.0"
	docs.SwaggerInfo.Host = "goapp-u5mew.ondigitalocean.app"
	docs.SwaggerInfo.BasePath = ""
	docs.SwaggerInfo.Schemes = []string{"https", "http"}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize metrics (required by logger)
	metrics := observability.New(observability.DefaultConfig())

	// Initialize logger
	logger, err := observability.NewLogger(cfg.Logging, metrics)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	// No sync method needed, removed defer logger.Sync()

	logger.Info("Application starting", observability.Field{Key: "environment", Value: cfg.App.Env}.ToZapField())

	// Initialize Database (PostgreSQL using go-pg)
	dbOpts := &pg.Options{
		Addr:     fmt.Sprintf("%s:%d", cfg.Database.Host, cfg.Database.Port),
		User:     cfg.Database.User,
		Password: cfg.Database.Password,
		Database: cfg.Database.Name,
		PoolSize: cfg.Database.MaxConnections,
	}

	// Configure SSL/TLS if required
	if cfg.Database.SSLMode == "require" || cfg.Database.SSLMode == "verify-ca" || cfg.Database.SSLMode == "verify-full" {
		dbOpts.TLSConfig = &tls.Config{
			InsecureSkipVerify: cfg.Database.SSLMode == "require", // For 'require', skip verification
		}
		logger.Info("TLS enabled for database connection", observability.Field{Key: "ssl_mode", Value: cfg.Database.SSLMode}.ToZapField())
	} else {
		logger.Info("TLS disabled for database connection", observability.Field{Key: "ssl_mode", Value: cfg.Database.SSLMode}.ToZapField())
	}

	logger.Info("Connecting to database",
		observability.Field{Key: "db_addr", Value: dbOpts.Addr}.ToZapField(),
		observability.Field{Key: "db_user", Value: dbOpts.User}.ToZapField(),
	)

	db := pg.Connect(dbOpts)

	// Test DB connection
	if err := db.Ping(context.Background()); err != nil {
		logger.Fatal("Failed to connect to database", err,
			observability.Field{Key: "db_host", Value: cfg.Database.Host}.ToZapField(),
			observability.Field{Key: "db_port", Value: cfg.Database.Port}.ToZapField(),
			observability.Field{Key: "db_name", Value: cfg.Database.Name}.ToZapField(),
		)
	}
	logger.Info("Database connection established")
	defer db.Close()

	// Initialize Redis Client
	var redisClient *redis.Client
	if cfg.Redis.Enabled {
		redisOpts := &redis.Options{
			Addr:     fmt.Sprintf("%s:%d", cfg.Redis.Host, cfg.Redis.Port),
			Password: cfg.Redis.Password,
			DB:       cfg.Redis.DB,
		}
		redisClient = redis.NewClient(redisOpts)
		// Test Redis connection
		if _, err := redisClient.Ping(context.Background()).Result(); err != nil {
			logger.Warn("Failed to connect to Redis, continuing without Redis",
				observability.Field{Key: "error", Value: err.Error()}.ToZapField(),
				observability.Field{Key: "redis_host", Value: cfg.Redis.Host}.ToZapField(),
				observability.Field{Key: "redis_port", Value: cfg.Redis.Port}.ToZapField(),
			)
			redisClient.Close()
			redisClient = nil
		} else {
			logger.Info("Redis connection established")
			defer redisClient.Close()
		}
	} else {
		logger.Info("Redis disabled in configuration")
	}

	// Initialize Encryption Service
	encryptionSvc, err := cfg.Security.BuildEncryptionService()
	if err != nil {
		logger.Fatal("Failed to initialize encryption service", err)
	}
	if encryptionSvc != nil {
		logger.Info("Encryption service initialized")
	}

	// Initialize Authentication Service
	authSvc := auth.NewService(db, cfg, audit.NewService(db))

	// Initialize Job Queue
	var jobQueue jobs.Queue
	if cfg.Jobs.Enabled && redisClient != nil {
		redisQueueConfig := jobs.DefaultRedisQueueConfig()
		jobQueue = jobs.NewRedisQueue(redisClient, redisQueueConfig)
		worker := &jobs.Worker{}              // Using struct literal until we find the correct constructor
		go worker.Start(context.Background()) // Start worker in background
		logger.Info("Job queue and workers initialized")
	} else {
		// Create a simple implementation of Queue interface
		jobQueue = &NoOpQueue{} // Using our local implementation
		logger.Info("Job queue disabled")
	}

	// Initialize Payment Service (Razorpay)
	var razorpayClient *razorpay.Client
	if cfg.Payment.Razorpay.Enabled {
		rzpConfig := &razorpay.Config{
			Currency: cfg.Payment.Razorpay.Currency,
			// Add other config if needed from razorpay/config.go
		}
		razorpayClient = razorpay.NewClient(cfg.Payment.Razorpay.KeyID, cfg.Payment.Razorpay.KeySecret, rzpConfig)
		logger.Info("Razorpay client initialized")
	}

	// Create underlying *sql.DB for services that need it (like PaymentService)
	// Note: This creates a separate connection pool. Consider if PaymentService
	// can be adapted to use go-pg directly or if a single pool is sufficient.
	stdDB, err := sql.Open("postgres", cfg.Database.GetDSN()) // Use standard sql driver with DSN
	if err != nil {
		logger.Fatal("Failed to open standard SQL DB connection", err)
	}
	defer stdDB.Close()

	// Initialize Payment Service but use it when needed
	services.NewPaymentService(stdDB, audit.NewService(db), razorpayClient, jobQueue)

	// Initialize Router
	router := api.NewRouter(cfg, logger, authSvc, encryptionSvc, db, redisClient)

	// Start server in a goroutine
	go func() {
		if err := router.Run(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Server failed to start", err)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logger.Info("Shutting down server...")

	// Create shutdown context but we don't need to use it directly since we're not implementing shutdown
	_, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Add shutdown logic for other services if needed (e.g., job worker)

	logger.Info("Server exiting")
}

// registerJobHandlers registers handlers for background jobs
func registerJobHandlers(worker *jobs.Worker, logger *observability.Logger, paymentSvc *services.PaymentService) error {
	// Email job handler
	err := worker.Register(jobs.JobTypeEmail, func(ctx context.Context, job *jobs.Job) error {
		start := time.Now()
		logger.Info("Processing email job",
			observability.Field{Key: "job_id", Value: job.ID}.ToZapField(),
		)

		// TODO: Implement actual email sending logic here

		logger.JobProcessed(ctx, string(job.Type), job.ID, time.Since(start), nil)
		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to register email job handler: %w", err)
	}

	// Payment job handler
	err = worker.Register(jobs.JobTypePayment, func(ctx context.Context, job *jobs.Job) error {
		start := time.Now()
		logger.Info("Processing payment job",
			observability.Field{Key: "job_id", Value: job.ID}.ToZapField(),
		)

		// TODO: Implement payment processing logic here

		logger.JobProcessed(ctx, string(job.Type), job.ID, time.Since(start), nil)
		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to register payment job handler: %w", err)
	}

	return nil
}

// Field is a helper function for logger fields
func Field(key string, value interface{}) observability.Field {
	return observability.Field{Key: key, Value: value}
}
