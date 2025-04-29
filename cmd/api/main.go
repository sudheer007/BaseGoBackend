package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"gobackend/docs"
	"gobackend/internal/api"
	"gobackend/internal/audit"
	"gobackend/internal/auth"
	"gobackend/internal/config"
	"gobackend/internal/database"
	"gobackend/internal/middleware"
	"gobackend/internal/services/thirdparty"

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

func main() {
	// Initialize Swagger docs
	docs.SwaggerInfo.Title = "GoBackend API"
	docs.SwaggerInfo.Description = "A secure Go backend API with Organization CRUD operations"
	docs.SwaggerInfo.Version = "1.0"
	docs.SwaggerInfo.Host = "localhost:8080"
	docs.SwaggerInfo.BasePath = ""
	docs.SwaggerInfo.Schemes = []string{"http", "https"}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Log the environment and debug status
	log.Printf("Application starting in [%s] mode", cfg.App.Env)
	log.Printf("Debug mode: %t", cfg.App.Debug)
	log.Printf("Log level: %s", cfg.App.LogLevel)

	// Initialize database
	db, err := database.New(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Create database schema
	if err := db.CreateSchema(); err != nil {
		log.Fatalf("Failed to create database schema: %v", err)
	}

	// Initialize encryption service
	encryptionSvc, err := cfg.Security.BuildEncryptionService()
	if err != nil {
		log.Fatalf("Failed to initialize encryption service: %v", err)
	}

	// Initialize services
	auditSvc := audit.NewService(db.DB)

	// Initialize auth service
	authSvc := auth.NewService(db.DB, cfg, auditSvc)

	// Initialize third-party services provider
	thirdPartyProvider := thirdparty.New(&cfg.ThirdParty)
	if err := thirdPartyProvider.Initialize(); err != nil {
		log.Printf("Warning: Failed to initialize some third-party services: %v", err)
	}

	// Initialize auth middleware
	authMiddleware := middleware.NewAuthMiddleware(authSvc)

	// Initialize router
	router := api.NewRouter(cfg, authSvc, encryptionSvc, db.DB)

	// Register AI routes
	api.RegisterAIRoutes(router.Engine, thirdPartyProvider, authMiddleware)

	// Set up graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-quit
		fmt.Println("Shutting down server...")
		// Perform cleanup here
	}()

	// Start the server
	log.Printf("Starting server on port %d...", cfg.App.Port)
	log.Printf("Swagger documentation available at: http://localhost:%d/swagger/index.html", cfg.App.Port)
	if err := router.Run(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
