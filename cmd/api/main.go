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
	"gobackend/internal/security"

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

// @host  goapp-u5mew.ondigitalocean.app
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
	docs.SwaggerInfo.Host = "goapp-u5mew.ondigitalocean.app"
	docs.SwaggerInfo.BasePath = ""
	docs.SwaggerInfo.Schemes = []string{"https", "http"}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Set up database connection
	db, err := database.New(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Create database schema
	/*if err := db.CreateSchema(); err != nil {
		log.Fatalf("Failed to create database schema: %v", err)
	}
	*/
	// Initialize encryption service
	var encryptionSvc *security.EncryptionService
	if cfg.Security.FieldEncryption {
		encryptionSvc, err = cfg.Security.BuildEncryptionService()
		if err != nil {
			log.Printf("Warning: Failed to initialize encryption service: %v", err)
		} else {
			log.Println("Field-level encryption enabled")
		}
	}

	// Initialize services
	auditSvc := audit.NewService(db.DB)
	authSvc := auth.NewService(db.DB, cfg, auditSvc)

	// Create and set up the router
	router := api.NewRouter(cfg, authSvc, encryptionSvc, db.DB)

	// Set up graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-quit
		fmt.Println("Shutting down server...")
		// Perform cleanup here
	}()

	// Start the server
	fmt.Printf("Starting server on port %d...\n", cfg.App.Port)
	fmt.Printf("Swagger documentation available at: https://goapp-u5mew.ondigitalocean.app/swagger/index.html\n")
	if err := router.Run(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
