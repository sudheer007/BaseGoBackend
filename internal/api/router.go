package api

import (
	"fmt"
	"strings"

	"gobackend/internal/audit"
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
	googleAuthSvc *auth.GoogleService
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

	// Initialize Google Auth service
	auditSvc := audit.NewService(db)
	googleAuthSvc := auth.NewGoogleService(db, cfg, auditSvc, authSvc)

	router := &Router{
		Engine:        r,
		cfg:           cfg,
		db:            db,
		redisClient:   redisClient,
		authService:   authSvc,
		encryptionSvc: encryptionSvc,
		logger:        logger,
		googleAuthSvc: googleAuthSvc,
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
			authGroup.POST("/refresh", r.RefreshToken)
			authGroup.POST("/logout", r.Logout)

			// Google Auth endpoints
			googleAuthGroup := authGroup.Group("/google")
			{
				googleAuthGroup.POST("/login", r.GoogleLogin)

				// These routes require authentication
				googleAuthAuthenticatedGroup := googleAuthGroup.Group("")
				googleAuthAuthenticatedGroup.Use(middleware.NewAuthMiddleware(r.authService).Authenticate())
				{
					googleAuthAuthenticatedGroup.POST("/logout", r.GoogleLogout)
					googleAuthAuthenticatedGroup.GET("/user", r.GoogleUser)
				}
			}
		}

		// Initialize repositories
		userRepo := data.NewUserRepository(r.db)
		orgRepo := data.NewOrganizationRepository(r.db)

		// Initialize services
		auditSvc := audit.NewService(r.db)
		userService := services.NewUserService(userRepo, auditSvc)
		orgService := services.NewOrganizationService(orgRepo, r.db)
		teamService := services.NewTeamService(r.db)
		authzService := services.NewAuthorizationService(r.db)
		recordingsService := services.NewRecordingsService()
		meetingsService := services.NewMeetingsService()
		userConfigService := services.NewUserConfigService(r.db)

		// Initialize Spaces service
		spacesConfig := services.SpacesConfig{
			AccessKey: r.cfg.Storage.Spaces.AccessKey,
			SecretKey: r.cfg.Storage.Spaces.SecretKey,
			Endpoint:  r.cfg.Storage.Spaces.Endpoint,
			Region:    r.cfg.Storage.Spaces.Region,
			Bucket:    r.cfg.Storage.Spaces.Bucket,
			CDNURL:    r.cfg.Storage.Spaces.CDNURL,
		}
		spacesService, err := services.NewSpacesService(spacesConfig)
		if err != nil {
			r.logger.Error("Failed to initialize Spaces service", err)
		}

		// Initialize handlers
		userHandlers := NewUserHandlers(userService)
		orgHandlers := NewOrganizationHandlers(orgService)
		teamHandlers := NewTeamHandlers(teamService)
		authzHandlers := NewAuthorizationHandlers(authzService)
		recordingsHandlers := NewRecordingsHandlers(recordingsService)
		meetingsHandlers := NewMeetingsHandlers(meetingsService)
		userConfigHandlers := NewUserConfigHandlers(userConfigService)
		spacesHandlers := NewSpacesHandlers(spacesService)

		authMiddleware := middleware.NewAuthMiddleware(r.authService)
		authzMiddleware := middleware.NewAuthorizationMiddleware(authzService)

		// Seed default permissions (consider doing this elsewhere, like main.go)
		if err := authzService.SeedDefaultPermissions(); err != nil {
			r.logger.Error("Failed to seed default permissions", err)
		}

		// Public user endpoint
		v1.POST("/users", userHandlers.AddUser)

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
				users.GET("", authzMiddleware.RequirePermission("user", "list"), userHandlers.ListUsers)
				users.GET("/:id", authzMiddleware.RequireUserAccess(models.AccessLevelReadOnly), userHandlers.GetUser)

				// User configuration endpoints
				users.POST("/update-user-config", userConfigHandlers.UpdateUserConfig)

				// Legacy user endpoints (these can be updated to use the new user handlers)
				users.PUT("/:id", authzMiddleware.RequireUserAccess(models.AccessLevelModify), r.UpdateUser)
				users.PUT("/:id/password", authzMiddleware.RequireUserAccess(models.AccessLevelModify), r.ChangePassword)
				users.PUT("/:id/mfa", authzMiddleware.RequireUserAccess(models.AccessLevelModify), r.ConfigureMFA)
				users.PUT("/:id/role", authzMiddleware.RequirePermission("user", "update"), r.UpdateUserRole)

				// Recordings endpoints
				users.GET("/:user_id/recordings", recordingsHandlers.GetUserRecordings)

				// Meetings endpoints
				users.GET("/:user_id/meetings", meetingsHandlers.GetUserMeetings)

				userOrgs := users.Group("/:userId/managed-organizations")
				userOrgs.Use(authzMiddleware.RequirePermission("organization", "list"))
				{
					userOrgs.GET("", orgHandlers.ListUserManagedOrganizations)
					userOrgs.POST("", authzMiddleware.RequirePermission("organization", "create"), orgHandlers.AssignOrganizationToUser)
					userOrgs.DELETE("/:organizationId", authzMiddleware.RequirePermission("organization", "delete"), orgHandlers.UnassignOrganizationFromUser)
				}
			}

			// File upload endpoint
			authenticated.POST("/upload-spaces-v2", spacesHandlers.UploadSpacesV2)
			authenticated.POST("/upload-spaces", spacesHandlers.UploadSpaces)
			authenticated.GET("/spaces-health", spacesHandlers.SpacesHealth)

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

			// Meetings routes
			meetings := authenticated.Group("/meetings")
			{
				meetings.POST("/setup", meetingsHandlers.SetupMeeting)
				meetings.POST("/upcoming-meetings", meetingsHandlers.UpcomingMeetings)
				meetings.POST("/add-custom-script", meetingsHandlers.AddCustomScript)
				meetings.POST("/display-topics", meetingsHandlers.DisplayTopics)
				meetings.POST("/get-custom-script", meetingsHandlers.GetCustomScript)
				meetings.POST("/delete-custom-scripts", meetingsHandlers.DeleteCustomScripts)
			}
		}
	}
}

// GoogleLogin handles Google OAuth login
func (r *Router) GoogleLogin(c *gin.Context) {
	handlers := NewGoogleAuthHandlers(r.googleAuthSvc)
	handlers.Login(c)
}

// GoogleLogout handles Google OAuth logout
func (r *Router) GoogleLogout(c *gin.Context) {
	handlers := NewGoogleAuthHandlers(r.googleAuthSvc)
	handlers.Logout(c)
}

// GoogleUser returns the current user's info from a Google auth token
func (r *Router) GoogleUser(c *gin.Context) {
	handlers := NewGoogleAuthHandlers(r.googleAuthSvc)
	handlers.GetUserInfo(c)
}
