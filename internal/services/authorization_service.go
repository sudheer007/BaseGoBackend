package services

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"gobackend/internal/models"

	"github.com/go-pg/pg/v10"
	"github.com/google/uuid"
)

// Authorization errors
var (
	ErrPermissionDenied    = errors.New("permission denied")
	ErrRoleNotFound        = errors.New("role not found")
	ErrInvalidResource     = errors.New("invalid resource")
	ErrInvalidAction       = errors.New("invalid action")
	ErrInvalidAccessLevel  = errors.New("invalid access level")
	ErrResourceScopeExists = errors.New("resource scope already exists")
)

// AuthorizationService provides methods for authorization
type AuthorizationService struct {
	db *pg.DB
}

// NewAuthorizationService creates a new authorization service
func NewAuthorizationService(db *pg.DB) *AuthorizationService {
	return &AuthorizationService{
		db: db,
	}
}

// HasPermission checks if a user has a specific permission (resource + action) based on their role
func (s *AuthorizationService) HasPermission(ctx context.Context, userID uuid.UUID, resource, action string) (bool, error) {
	// 1. Get the user with their role
	var user models.User
	err := s.db.Model(&user).
		Where("id = ? AND deleted_at IS NULL AND active = TRUE", userID).
		Select()

	if err != nil {
		if err == pg.ErrNoRows {
			return false, nil // User not found
		}
		return false, fmt.Errorf("failed to get user: %w", err)
	}

	// 2. Check for super_admin role (has all permissions)
	if user.Role == models.RoleSuperAdmin {
		return true, nil
	}

	// 3. Check role-based permissions
	exists, err := s.db.Model((*models.RolePermission)(nil)).
		Join("JOIN permissions AS p ON p.id = role_permission.permission_id").
		Where("role_permission.role = ? AND p.resource = ? AND p.action = ?", user.Role, resource, action).
		Exists()

	if err != nil && err != pg.ErrNoRows {
		return false, fmt.Errorf("failed to check permissions: %w", err)
	}

	return exists, nil
}

// HasResourceAccess checks if a user has access to a specific resource instance
func (s *AuthorizationService) HasResourceAccess(ctx context.Context, userID, resourceID uuid.UUID, resourceType string, minAccessLevel models.AccessLevel) (bool, error) {
	// 1. Check resource-specific permission
	var scope models.ResourceScope
	err := s.db.Model(&scope).
		Where("user_id = ? AND resource_id = ? AND resource_type = ?", userID, resourceID, resourceType).
		Select()

	if err != nil {
		if err == pg.ErrNoRows {
			// 2. If no direct permission, check role-based access for the resource type
			return s.checkRoleBasedAccess(ctx, userID, resourceType, resourceID)
		}
		return false, fmt.Errorf("failed to check resource access: %w", err)
	}

	// 3. Compare access levels
	return s.isAccessLevelSufficient(scope.AccessLevel, minAccessLevel), nil
}

// isAccessLevelSufficient checks if the actual access level is sufficient compared to the minimum required
func (s *AuthorizationService) isAccessLevelSufficient(actual, minimum models.AccessLevel) bool {
	// Define access level hierarchy (from highest to lowest)
	levels := map[models.AccessLevel]int{
		models.AccessLevelOwner:     6,
		models.AccessLevelAdmin:     5,
		models.AccessLevelManage:    4,
		models.AccessLevelModify:    3,
		models.AccessLevelReadWrite: 2,
		models.AccessLevelReadOnly:  1,
	}

	actualLevel, actualExists := levels[actual]
	minLevel, minExists := levels[minimum]

	if !actualExists || !minExists {
		return false
	}

	return actualLevel >= minLevel
}

// checkRoleBasedAccess checks if the user has role-based access to a resource
func (s *AuthorizationService) checkRoleBasedAccess(ctx context.Context, userID uuid.UUID, resourceType string, resourceID uuid.UUID) (bool, error) {
	// Get user with their role
	var user models.User
	err := s.db.Model(&user).
		Where("id = ? AND deleted_at IS NULL AND active = TRUE", userID).
		Select()

	if err != nil {
		if err == pg.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("failed to get user: %w", err)
	}

	// Super admin has access to everything
	if user.Role == models.RoleSuperAdmin {
		return true, nil
	}

	switch resourceType {
	case "organization":
		// Admin has access to their organization
		if user.Role == models.RoleAdmin && user.OrganizationID == resourceID {
			return true, nil
		}
		return false, nil

	case "team":
		// Manager can access teams in their organization, but need to check team ownership
		if user.Role == models.RoleManager {
			var team models.Team
			err := s.db.Model(&team).
				Where("id = ? AND organization_id = ?", resourceID, user.OrganizationID).
				Select()

			if err != nil {
				if err == pg.ErrNoRows {
					return false, nil
				}
				return false, fmt.Errorf("failed to get team: %w", err)
			}

			// Check if user is member of the team
			memberExists, err := s.db.Model((*models.TeamMember)(nil)).
				Where("team_id = ? AND user_id = ?", team.ID, userID).
				Exists()

			return memberExists, err
		}
		return false, nil

	case "user":
		// Users can access their own data
		return userID == resourceID, nil

	default:
		return false, nil
	}
}

// CreateResourceScope creates a new resource scope (user-resource permission)
func (s *AuthorizationService) CreateResourceScope(ctx context.Context, scope *models.ResourceScope) error {
	// Check if scope already exists
	exists, err := s.db.Model((*models.ResourceScope)(nil)).
		Where("user_id = ? AND resource_id = ? AND resource_type = ?",
			scope.UserID, scope.ResourceID, scope.ResourceType).
		Exists()

	if err != nil {
		return fmt.Errorf("failed to check resource scope: %w", err)
	}

	if exists {
		return ErrResourceScopeExists
	}

	// Validate resource type
	validTypes := map[string]bool{"organization": true, "team": true, "user": true}
	if !validTypes[scope.ResourceType] {
		return ErrInvalidResource
	}

	// Insert the scope
	_, err = s.db.Model(scope).Insert()
	if err != nil {
		return fmt.Errorf("failed to create resource scope: %w", err)
	}

	return nil
}

// UpdateResourceScope updates an existing resource scope
func (s *AuthorizationService) UpdateResourceScope(ctx context.Context, scope *models.ResourceScope) error {
	_, err := s.db.Model(scope).
		WherePK().
		Set("access_level = ?", scope.AccessLevel).
		Set("updated_at = now()").
		Update()

	if err != nil {
		return fmt.Errorf("failed to update resource scope: %w", err)
	}

	return nil
}

// DeleteResourceScope deletes a resource scope
func (s *AuthorizationService) DeleteResourceScope(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.Model((*models.ResourceScope)(nil)).
		Where("id = ?", id).
		Delete()

	if err != nil {
		return fmt.Errorf("failed to delete resource scope: %w", err)
	}

	return nil
}

// GetPermissions gets all available permissions
func (s *AuthorizationService) GetPermissions(ctx context.Context) ([]models.Permission, error) {
	var permissions []models.Permission
	err := s.db.Model(&permissions).Select()
	if err != nil {
		return nil, fmt.Errorf("failed to get permissions: %w", err)
	}

	return permissions, nil
}

// GetRolePermissions gets permissions assigned to a specific role
func (s *AuthorizationService) GetRolePermissions(ctx context.Context, role string) ([]models.Permission, error) {
	var permissions []models.Permission
	err := s.db.Model(&permissions).
		Join("JOIN role_permissions AS rp ON rp.permission_id = permission.id").
		Where("rp.role = ?", role).
		Select()

	if err != nil {
		return nil, fmt.Errorf("failed to get role permissions: %w", err)
	}

	return permissions, nil
}

// AssignPermissionToRole assigns a permission to a role
func (s *AuthorizationService) AssignPermissionToRole(ctx context.Context, role string, permissionID uuid.UUID) error {
	// Validate role
	validRoles := map[string]bool{
		string(models.RoleSuperAdmin): true,
		string(models.RoleAdmin):      true,
		string(models.RoleManager):    true,
		string(models.RoleUser):       true,
		string(models.RoleReadOnly):   true,
	}

	if !validRoles[role] {
		return ErrRoleNotFound
	}

	// Check if permission exists
	exists, err := s.db.Model((*models.Permission)(nil)).
		Where("id = ?", permissionID).
		Exists()

	if err != nil {
		return fmt.Errorf("failed to check permission: %w", err)
	}

	if !exists {
		return errors.New("permission not found")
	}

	// Create role-permission mapping
	_, err = s.db.Model(&models.RolePermission{
		RoleID:       role,
		PermissionID: permissionID,
		CreatedAt:    time.Now(),
	}).Insert()

	if err != nil {
		return fmt.Errorf("failed to assign permission to role: %w", err)
	}

	return nil
}

// RemovePermissionFromRole removes a permission from a role
func (s *AuthorizationService) RemovePermissionFromRole(ctx context.Context, role string, permissionID uuid.UUID) error {
	_, err := s.db.Model((*models.RolePermission)(nil)).
		Where("role = ? AND permission_id = ?", role, permissionID).
		Delete()

	if err != nil {
		return fmt.Errorf("failed to remove permission from role: %w", err)
	}

	return nil
}

// SeedDefaultPermissions creates default permissions and role assignments
func (s *AuthorizationService) SeedDefaultPermissions() error {
	// Create default permissions if they don't exist
	permissions := []struct {
		Resource    string
		Action      string
		Description string
	}{
		{"organization", "create", "Create an organization"},
		{"organization", "read", "View organization details"},
		{"organization", "update", "Update organization details"},
		{"organization", "delete", "Delete an organization"},
		{"organization", "list", "List all organizations"},

		{"team", "create", "Create a team"},
		{"team", "read", "View team details"},
		{"team", "update", "Update team details"},
		{"team", "delete", "Delete a team"},
		{"team", "list", "List all teams"},
		{"team", "manage_members", "Manage team members"},

		{"user", "create", "Create a user"},
		{"user", "read", "View user details"},
		{"user", "update", "Update user details"},
		{"user", "delete", "Delete a user"},
		{"user", "list", "List all users"},
		{"user", "change_role", "Change user role"},

		{"permission", "assign", "Assign permissions"},
		{"permission", "revoke", "Revoke permissions"},
		{"permission", "list", "List permissions"},
	}

	for _, p := range permissions {
		exists, err := s.db.Model((*models.Permission)(nil)).
			Where("resource = ? AND action = ?", p.Resource, p.Action).
			Exists()

		if err != nil {
			return fmt.Errorf("failed to check permission existence: %w", err)
		}

		if !exists {
			permission := &models.Permission{
				Resource:    p.Resource,
				Action:      p.Action,
				Description: p.Description,
			}
			_, err = s.db.Model(permission).Insert()
			if err != nil {
				return fmt.Errorf("failed to create permission: %w", err)
			}
		}
	}

	// Assign permissions to roles
	roles := []string{
		string(models.RoleSuperAdmin),
		string(models.RoleAdmin),
		string(models.RoleManager),
		string(models.RoleUser),
		string(models.RoleReadOnly),
	}

	// Get all permissions
	var allPermissions []models.Permission
	err := s.db.Model(&allPermissions).Select()
	if err != nil {
		return fmt.Errorf("failed to get permissions: %w", err)
	}

	// Create role-permission mappings based on role
	for _, role := range roles {
		for _, permission := range allPermissions {
			// Skip if mapping already exists
			exists, err := s.db.Model((*models.RolePermission)(nil)).
				Where("role = ? AND permission_id = ?", role, permission.ID).
				Exists()

			if err != nil {
				return fmt.Errorf("failed to check role permission: %w", err)
			}

			if exists {
				continue
			}

			// Determine if this permission should be assigned to this role
			shouldAssign := false

			// Super admin gets all permissions
			if role == string(models.RoleSuperAdmin) {
				shouldAssign = true
			} else if role == string(models.RoleAdmin) {
				// Admin gets all permissions except organization delete and user permission management
				shouldAssign = !(permission.Resource == "organization" && permission.Action == "delete") &&
					!(permission.Resource == "permission" && (permission.Action == "assign" || permission.Action == "revoke"))
			} else if role == string(models.RoleManager) {
				// Manager gets team permissions and limited user permissions
				shouldAssign = (permission.Resource == "team") ||
					(permission.Resource == "user" && permission.Action != "delete" && permission.Action != "change_role")
			} else if role == string(models.RoleUser) {
				// Regular user gets limited permissions
				shouldAssign = (permission.Resource == "user" && permission.Action == "read") ||
					(permission.Resource == "team" && (permission.Action == "read" || permission.Action == "list"))
			} else if role == string(models.RoleReadOnly) {
				// Read-only user gets only read permissions
				shouldAssign = permission.Action == "read" || permission.Action == "list"
			}

			if shouldAssign {
				_, err = s.db.Model(&models.RolePermission{
					RoleID:       role,
					PermissionID: permission.ID,
				}).Insert()

				if err != nil {
					return fmt.Errorf("failed to assign permission to role: %w", err)
				}
			}
		}
	}

	log.Println("Default permissions seeded successfully")
	return nil
}
