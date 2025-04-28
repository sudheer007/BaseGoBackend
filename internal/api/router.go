package api

import (
	"log"
	"strconv"

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

	// CORS
	r.Engine.Use(middleware.CORS(r.Config.CORS.AllowedOrigins))

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
			auth.POST("/signup", r.Signup)
			auth.POST("/refresh", r.RefreshToken)
			auth.POST("/logout", r.Logout)
		}

		// Create services and repositories
		orgRepo := data.NewOrganizationRepository(r.DB)
		orgService := services.NewOrganizationService(orgRepo, r.DB)
		orgHandlers := NewOrganizationHandlers(orgService)

		// Create team service and handlers
		teamService := services.NewTeamService(r.DB)
		teamHandlers := NewTeamHandlers(teamService)

		// Create authorization service and handlers
		authzService := services.NewAuthorizationService(r.DB)
		authzHandlers := NewAuthorizationHandlers(authzService)

		// Initialize the authorization middleware
		authMiddleware := middleware.NewAuthMiddleware(r.AuthService)
		authzMiddleware := middleware.NewAuthorizationMiddleware(authzService)

		// Seed default permissions
		if err := authzService.SeedDefaultPermissions(); err != nil {
			// Log the error but continue
			log.Printf("Failed to seed default permissions: %v", err)
		}

		// Organizations routes (now with proper authorization)
		orgs := v1.Group("/organizations")
		{
			// Apply authentication middleware
			orgs.Use(authMiddleware.Authenticate())

			// List organizations (requires permission to list organizations)
			orgs.GET("", authzMiddleware.RequirePermission("organization", "list"), orgHandlers.ListOrganizations)

			// List organizations for current user
			orgs.GET("/my", orgHandlers.ListMyOrganizations)

			// Get single organization (requires resource access)
			orgs.GET("/:id", authzMiddleware.RequireOrganizationAccess(models.AccessLevelReadOnly), orgHandlers.GetOrganization)

			// Create organization (requires super admin role)
			orgs.POST("", authzMiddleware.RequirePermission("organization", "create"), orgHandlers.CreateOrganization)

			// Update organization (requires admin level access to the organization)
			orgs.PUT("/:id", authzMiddleware.RequireOrganizationAccess(models.AccessLevelAdmin), orgHandlers.UpdateOrganization)

			// Delete organization (requires owner level access)
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

				// New routes for super admin organization management
				userOrgs := users.Group("/:userId/managed-organizations")
				userOrgs.Use(authzMiddleware.RequirePermission("organization", "list"))
				{
					// List organizations managed by a user
					userOrgs.GET("", orgHandlers.ListUserManagedOrganizations)

					// Assign organization to user (requires superadmin permission)
					userOrgs.POST("", authzMiddleware.RequirePermission("organization", "create"), orgHandlers.AssignOrganizationToUser)

					// Unassign organization from user
					userOrgs.DELETE("/:organizationId", authzMiddleware.RequirePermission("organization", "delete"), orgHandlers.UnassignOrganizationFromUser)
				}
			}

			// Team routes with team handlers
			teams := authenticated.Group("/teams")
			{
				teams.GET("", authzMiddleware.RequirePermission("team", "list"), teamHandlers.ListTeams)
				teams.GET("/:id", authzMiddleware.RequireTeamAccess(models.AccessLevelReadOnly), teamHandlers.GetTeam)
				teams.POST("", authzMiddleware.RequirePermission("team", "create"), teamHandlers.CreateTeam)
				teams.PUT("/:id", authzMiddleware.RequireTeamAccess(models.AccessLevelModify), teamHandlers.UpdateTeam)
				teams.DELETE("/:id", authzMiddleware.RequireTeamAccess(models.AccessLevelAdmin), teamHandlers.DeleteTeam)

				// Team members management
				teams.GET("/:id/members", authzMiddleware.RequireTeamAccess(models.AccessLevelReadOnly), teamHandlers.ListTeamMembers)
				teams.POST("/:id/members", authzMiddleware.RequireTeamAccess(models.AccessLevelManage), teamHandlers.AddTeamMember)
				teams.DELETE("/:id/members/:userId", authzMiddleware.RequireTeamAccess(models.AccessLevelManage), teamHandlers.RemoveTeamMember)
			}

			// Tenant routes
			tenants := authenticated.Group("/tenants")
			{
				tenants.GET("", authzMiddleware.RequirePermission("organization", "list"), r.ListTenants)
				tenants.GET("/:id", authMiddleware.RequireTenantAccess(), r.GetTenant)
				tenants.PUT("/:id", authzMiddleware.RequirePermission("organization", "update"), r.UpdateTenant)
			}

			// Audit log routes
			audits := authenticated.Group("/audit-logs")
			{
				audits.GET("", authzMiddleware.RequirePermission("organization", "read"), r.ListAuditLogs)
			}

			// Authorization routes (only accessible to super admins)
			permissions := authenticated.Group("/permissions")
			permissions.Use(authzMiddleware.RequirePermission("permission", "list"))
			{
				permissions.GET("", authzHandlers.GetPermissions)
			}

			// Role permissions routes
			roles := authenticated.Group("/roles")
			{
				// Get role permissions (requires permission to list permissions)
				roles.GET("/:role/permissions", authzMiddleware.RequirePermission("permission", "list"),
					authzHandlers.GetRolePermissions)

				// Assign permission to role (requires permission to assign permissions)
				roles.POST("/:role/permissions", authzMiddleware.RequirePermission("permission", "assign"),
					authzHandlers.AssignPermissionToRole)

				// Remove permission from role (requires permission to revoke permissions)
				roles.DELETE("/:role/permissions/:permissionId", authzMiddleware.RequirePermission("permission", "revoke"),
					authzHandlers.RemovePermissionFromRole)
			}

			// Resource scopes routes
			scopes := authenticated.Group("/resource-scopes")
			{
				// Create resource scope (requires super admin or admin role)
				scopes.POST("", authzMiddleware.RequirePermission("permission", "assign"),
					authzHandlers.CreateResourceScope)

				// Update resource scope (requires super admin or admin role)
				scopes.PUT("/:id", authzMiddleware.RequirePermission("permission", "assign"),
					authzHandlers.UpdateResourceScope)

				// Delete resource scope (requires super admin or admin role)
				scopes.DELETE("/:id", authzMiddleware.RequirePermission("permission", "revoke"),
					authzHandlers.DeleteResourceScope)
			}
		}
	}
}

// Run starts the API server
func (r *Router) Run() error {
	return r.Engine.Run(":" + strconv.Itoa(r.Config.App.Port))
}
