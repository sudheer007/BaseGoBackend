package api

import (
	"fmt"
	"strings"

	"gobackend/internal/auth"
	"gobackend/internal/config"
	"gobackend/internal/data"
	"gobackend/internal/middleware"
	"gobackend/internal/models"
	"gobackend/internal/observability"
	"gobackend/internal/security"
	"gobackend/internal/services"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/go-pg/pg/v10"
	"github.com/go-redis/redis/v8"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// Router wraps the Gin engine and holds dependencies
type Router struct {
	Engine        *gin.Engine
	cfg           *config.Config
	db            *pg.DB
	redisClient   *redis.Client
	authService   *auth.Service
	encryptionSvc *security.EncryptionService
	logger        *observability.Logger
}

// NewRouter creates a new router with dependencies
func NewRouter(cfg *config.Config, logger *observability.Logger, authSvc *auth.Service, encryptionSvc *security.EncryptionService, db *pg.DB, redisClient *redis.Client) *Router {
	// Set Gin mode based on config
	if cfg.App.Debug {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()

	router := &Router{
		Engine:        r,
		cfg:           cfg,
		db:            db,
		redisClient:   redisClient,
		authService:   authSvc,
		encryptionSvc: encryptionSvc,
		logger:        logger,
	}

	// Setup middleware first
	router.setupMiddleware()

	// Then setup routes
	router.setupRoutes()

	return router
}

// Run starts the HTTP server
func (r *Router) Run() error {
	addr := fmt.Sprintf(":%d", r.cfg.App.Port)
	r.logger.Info("Starting server", observability.Field{Key: "address", Value: addr}.ToZapField())
	return r.Engine.Run(addr)
}

// UseMiddleware adds middleware to the router (potentially redundant if setupMiddleware handles all)
// func (r *Router) UseMiddleware(middleware ...gin.HandlerFunc) {
// 	r.Engine.Use(middleware...)
// }

// setupMiddleware configures middleware for the router
func (r *Router) setupMiddleware() {
	// Recovery middleware first
	r.Engine.Use(gin.Recovery())

	// Request ID middleware
	r.Engine.Use(RequestIDMiddleware())

	// Custom logging middleware
	r.Engine.Use(RequestLogger(r.logger))

	// Security headers
	r.Engine.Use(middleware.SecurityHeaders())

	// CORS
	if r.cfg.CORS.AllowedOrigins != "" {
		corsConfig := cors.Config{
			AllowOrigins:     strings.Split(r.cfg.CORS.AllowedOrigins, ","),
			AllowMethods:     strings.Split(r.cfg.CORS.AllowedMethods, ","),
			AllowHeaders:     strings.Split(r.cfg.CORS.AllowedHeaders, ","),
			ExposeHeaders:    strings.Split(r.cfg.CORS.ExposedHeaders, ","),
			AllowCredentials: r.cfg.CORS.AllowCredentials,
			MaxAge:           r.cfg.CORS.MaxAge,
		}
		r.Engine.Use(cors.New(corsConfig))
	}

	// Rate limiting
	if r.cfg.RateLimit.Enabled && r.redisClient != nil {
		rateLimiterConfig := &middleware.RateLimiterConfig{
			RPS:         r.cfg.RateLimit.RequestsPerSecond,
			Burst:       r.cfg.RateLimit.Burst,
			ExpireIn:    r.cfg.RateLimit.ExpireMinutes,
			RedisClient: r.redisClient,
		}
		rateLimiter := middleware.NewRateLimiterMiddleware(rateLimiterConfig)
		r.Engine.Use(rateLimiter.Limit())
	} else if r.cfg.RateLimit.Enabled {
		r.logger.Warn("Rate limiting enabled in config but Redis client is not available")
	}

	// Field-level encryption
	if r.encryptionSvc != nil {
		r.Engine.Use(middleware.NewEncryptionMiddleware(r.encryptionSvc))
	}

	// Error Handling Middleware (add this last)
	r.Engine.Use(ErrorHandler(r.logger))
}

// setupRoutes configures the API routes
func (r *Router) setupRoutes() {
	// Health check
	r.Engine.GET("/health", r.HealthCheck)

	// Metrics endpoint
	if r.cfg.Metrics.Enabled {
		r.Engine.GET("/metrics", gin.WrapH(promhttp.Handler()))
	}

	// Swagger Docs
	swaggerURL := ginSwagger.URL("/swagger/doc.json")
	r.Engine.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler, swaggerURL))

	// API v1 routes
	v1 := r.Engine.Group("/api/v1")
	{
		// Public routes (no authentication required)
		authGroup := v1.Group("/auth")
		{
			authGroup.POST("/login", r.Login)
			authGroup.POST("/signup", r.Signup)
			authGroup.POST("/refresh", r.RefreshToken)
			authGroup.POST("/logout", r.Logout)
		}

		// Initialize services and handlers within the route setup
		orgRepo := data.NewOrganizationRepository(r.db)
		orgService := services.NewOrganizationService(orgRepo, r.db)
		orgHandlers := NewOrganizationHandlers(orgService)

		teamService := services.NewTeamService(r.db)
		teamHandlers := NewTeamHandlers(teamService)

		authzService := services.NewAuthorizationService(r.db)
		authzHandlers := NewAuthorizationHandlers(authzService)

		authMiddleware := middleware.NewAuthMiddleware(r.authService)
		authzMiddleware := middleware.NewAuthorizationMiddleware(authzService)

		// Seed default permissions (consider doing this elsewhere, like main.go)
		if err := authzService.SeedDefaultPermissions(); err != nil {
			r.logger.Error("Failed to seed default permissions", err)
		}

		// Organizations routes
		orgs := v1.Group("/organizations")
		{
			orgs.Use(authMiddleware.Authenticate())
			orgs.GET("", authzMiddleware.RequirePermission("organization", "list"), orgHandlers.ListOrganizations)
			orgs.GET("/my", orgHandlers.ListMyOrganizations)
			orgs.GET("/:id", authzMiddleware.RequireOrganizationAccess(models.AccessLevelReadOnly), orgHandlers.GetOrganization)
			orgs.POST("", authzMiddleware.RequirePermission("organization", "create"), orgHandlers.CreateOrganization)
			orgs.PUT("/:id", authzMiddleware.RequireOrganizationAccess(models.AccessLevelAdmin), orgHandlers.UpdateOrganization)
			orgs.DELETE("/:id", authzMiddleware.RequireOrganizationAccess(models.AccessLevelOwner), orgHandlers.DeleteOrganization)
		}

		// Authenticated routes
		authenticated := v1.Group("")
		authenticated.Use(authMiddleware.Authenticate())
		{
			// User routes
			users := authenticated.Group("/users")
			{
				users.GET("", authzMiddleware.RequirePermission("user", "list"), r.ListUsers)
				users.GET("/:id", authzMiddleware.RequireUserAccess(models.AccessLevelReadOnly), r.GetUser)
				users.PUT("/:id", authzMiddleware.RequireUserAccess(models.AccessLevelModify), r.UpdateUser)
				users.PUT("/:id/password", authzMiddleware.RequireUserAccess(models.AccessLevelModify), r.ChangePassword)
				users.PUT("/:id/mfa", authzMiddleware.RequireUserAccess(models.AccessLevelModify), r.ConfigureMFA)
				users.PUT("/:id/role", authzMiddleware.RequirePermission("user", "update"), r.UpdateUserRole)

				userOrgs := users.Group("/:userId/managed-organizations")
				userOrgs.Use(authzMiddleware.RequirePermission("organization", "list"))
				{
					userOrgs.GET("", orgHandlers.ListUserManagedOrganizations)
					userOrgs.POST("", authzMiddleware.RequirePermission("organization", "create"), orgHandlers.AssignOrganizationToUser)
					userOrgs.DELETE("/:organizationId", authzMiddleware.RequirePermission("organization", "delete"), orgHandlers.UnassignOrganizationFromUser)
				}
			}

			// Team routes
			teams := authenticated.Group("/teams")
			{
				teams.GET("", authzMiddleware.RequirePermission("team", "list"), teamHandlers.ListTeams)
				teams.GET("/:id", authzMiddleware.RequireTeamAccess(models.AccessLevelReadOnly), teamHandlers.GetTeam)
				teams.POST("", authzMiddleware.RequirePermission("team", "create"), teamHandlers.CreateTeam)
				teams.PUT("/:id", authzMiddleware.RequireTeamAccess(models.AccessLevelModify), teamHandlers.UpdateTeam)
				teams.DELETE("/:id", authzMiddleware.RequireTeamAccess(models.AccessLevelAdmin), teamHandlers.DeleteTeam)

				teams.GET("/:id/members", authzMiddleware.RequireTeamAccess(models.AccessLevelReadOnly), teamHandlers.ListTeamMembers)
				teams.POST("/:id/members", authzMiddleware.RequireTeamAccess(models.AccessLevelManage), teamHandlers.AddTeamMember)
				teams.DELETE("/:id/members/:userId", authzMiddleware.RequireTeamAccess(models.AccessLevelManage), teamHandlers.RemoveTeamMember)
			}

			// Audit log routes
			audits := authenticated.Group("/audit-logs")
			audits.Use(authzMiddleware.RequirePermission("audit", "read"))
			{
				audits.GET("", r.ListAuditLogs)
			}

			// Authorization routes (only accessible to super admins)
			permissions := authenticated.Group("/permissions")
			permissions.Use(authzMiddleware.RequirePermission("permission", "manage"))
			{
				permissions.GET("", authzHandlers.GetPermissions)
				permissions.PUT("", authzHandlers.UpdatePermissions)
			}

			roles := authenticated.Group("/roles")
			roles.Use(authzMiddleware.RequirePermission("role", "manage"))
			{
				roles.GET("", authzHandlers.GetRoles)
				roles.POST("", authzHandlers.CreateRole)
				roles.PUT("/:roleName", authzHandlers.UpdateRole)
				roles.DELETE("/:roleName", authzHandlers.DeleteRole)
			}
		}
	}
}
