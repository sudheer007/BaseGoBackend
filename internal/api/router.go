package api

import (
	"strconv"
	"time"

	"gobackend/internal/auth"
	"gobackend/internal/config"
	"gobackend/internal/data"
	"gobackend/internal/middleware"
	"gobackend/internal/models"
	"gobackend/internal/security"
	"gobackend/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/go-pg/pg/v10"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Router is the main API router
type Router struct {
	Engine        *gin.Engine
	Config        *config.Config
	AuthService   *auth.Service
	EncryptionSvc *security.EncryptionService
	DB            *pg.DB
}

// NewRouter creates a new API router
func NewRouter(cfg *config.Config, authSvc *auth.Service, encryptionSvc *security.EncryptionService, db *pg.DB) *Router {
	// Set Gin mode based on environment
	if cfg.App.Env == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := &Router{
		Engine:        gin.New(),
		Config:        cfg,
		AuthService:   authSvc,
		EncryptionSvc: encryptionSvc,
		DB:            db,
	}

	// Set up middleware
	r.setupMiddleware()

	// Set up routes
	r.setupRoutes()

	// Set up Swagger
	SetupSwagger(r.Engine)

	return r
}

// setupMiddleware configures middleware for the router
func (r *Router) setupMiddleware() {
	// Recovery middleware
	r.Engine.Use(middleware.Recovery())

	// Request logging
	r.Engine.Use(middleware.RequestLogger())

	// Security headers
	r.Engine.Use(middleware.SecurityHeaders())

	// CORS - Use the comprehensive CORS middleware with proper HTTPS support
	corsConfig := &middleware.CORSConfig{
		AllowedOrigins: []string{
			"https://goapp-u5mew.ondigitalocean.app",
			"https://localhost:3000",
			"http://localhost:3000",
			"https://127.0.0.1:3000",
			"http://127.0.0.1:3000",
			"*", // Allow all origins for testing - remove in production
		},
		AllowedMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{
			"Origin",
			"Content-Type",
			"Accept",
			"Authorization",
			"X-Request-ID",
			"X-Requested-With",
			"Access-Control-Allow-Origin",
		},
		ExposeHeaders: []string{
			"Content-Length",
			"X-Request-ID",
			"X-RateLimit-Limit",
			"X-RateLimit-Remaining",
			"X-RateLimit-Reset",
		},
		AllowCredentials: true,
		AllowWildcard:    true,
		MaxAge:           12 * time.Hour,
	}
	r.Engine.Use(middleware.CORSMiddleware(corsConfig))

	// Rate limiting
	rateLimiter := middleware.NewRateLimit()
	r.Engine.Use(rateLimiter.Limit(
		float64(r.Config.RateLimit.Requests)/r.Config.RateLimit.Duration.Seconds(),
		r.Config.RateLimit.Requests,
	))

	// Field-level encryption
	if r.EncryptionSvc != nil {
		r.Engine.Use(middleware.NewEncryptionMiddleware(r.EncryptionSvc))
	}
}

// setupRoutes configures the API routes
func (r *Router) setupRoutes() {
	// Health check
	r.Engine.GET("/health", r.HealthCheck)

	// Metrics endpoint
	r.Engine.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// API v1 routes
	v1 := r.Engine.Group("/api/v1")
	{
		// Public routes (no authentication required)
		auth := v1.Group("/auth")
		{
			auth.POST("/login", r.Login)
			auth.POST("/refresh", r.RefreshToken)
			auth.POST("/logout", r.Logout)
		}

		// Create the organization repository and service
		orgRepo := data.NewOrganizationRepository(r.DB)
		orgService := services.NewOrganizationService(orgRepo)
		orgHandlers := NewOrganizationHandlers(orgService)

		// Organizations routes (no auth for now for testing purposes)
		orgs := v1.Group("/organizations")
		{
			orgs.GET("", orgHandlers.ListOrganizations)
			orgs.GET("/:id", orgHandlers.GetOrganization)
			orgs.POST("", orgHandlers.CreateOrganization)
			orgs.PUT("/:id", orgHandlers.UpdateOrganization)
			orgs.DELETE("/:id", orgHandlers.DeleteOrganization)
		}

		// Authenticated routes
		authMiddleware := middleware.NewAuthMiddleware(r.AuthService)
		authenticated := v1.Group("")
		authenticated.Use(authMiddleware.Authenticate())
		{
			// User routes
			users := authenticated.Group("/users")
			{
				users.GET("", authMiddleware.RequireRole(string(models.RoleAdmin), string(models.RoleManager)), r.ListUsers)
				users.GET("/:id", r.GetUser)
				users.PUT("/:id", r.UpdateUser)
				users.PUT("/:id/password", r.ChangePassword)
				users.PUT("/:id/mfa", r.ConfigureMFA)
			}

			// Tenant routes
			tenants := authenticated.Group("/tenants")
			{
				tenants.GET("", authMiddleware.RequireRole(string(models.RoleAdmin)), r.ListTenants)
				tenants.GET("/:id", authMiddleware.RequireTenantAccess(), r.GetTenant)
				tenants.PUT("/:id", authMiddleware.RequireRole(string(models.RoleAdmin)), r.UpdateTenant)
			}

			// Audit log routes
			audits := authenticated.Group("/audit-logs")
			{
				audits.GET("", authMiddleware.RequireRole(string(models.RoleAdmin), string(models.RoleManager)), r.ListAuditLogs)
			}
		}
	}
}

// Run starts the API server
func (r *Router) Run() error {
	return r.Engine.Run(":" + strconv.Itoa(r.Config.App.Port))
}
