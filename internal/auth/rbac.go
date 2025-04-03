package auth

import (
	"context"
	"fmt"
	"sync"

	"gobackend/internal/models"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/google/uuid"
)

// RBAC manages role-based access control
type RBAC struct {
	enforcer *casbin.Enforcer
	mutex    sync.RWMutex
}

// NewRBAC creates a new RBAC manager
func NewRBAC() (*RBAC, error) {
	// Define the RBAC model
	// g(r, p) means r has role p
	// g2(u, r) means user u has role r
	// p(r, res, act) means role r can perform action act on resource res
	modelText := `
	[request_definition]
	r = sub, obj, act

	[policy_definition]
	p = sub, obj, act

	[role_definition]
	g = _, _
	g2 = _, _

	[policy_effect]
	e = some(where (p.eft == allow))

	[matchers]
	m = g(r.sub, p.sub) && (p.obj == "*" || p.obj == r.obj || p.obj == r.obj + ":" + r.sub) && (p.act == "*" || p.act == r.act) || g2(r.sub, "super_admin")
	`

	// Create the model from text
	m, err := model.NewModelFromString(modelText)
	if err != nil {
		return nil, fmt.Errorf("failed to create RBAC model: %w", err)
	}

	// Create the enforcer with a memory adapter
	adapter := newMemoryAdapter()
	enforcer, err := casbin.NewEnforcer(m, adapter)
	if err != nil {
		return nil, fmt.Errorf("failed to create RBAC enforcer: %w", err)
	}

	// Initialize the RBAC system with default rules
	initializeDefaultPolicies(enforcer)

	return &RBAC{
		enforcer: enforcer,
		mutex:    sync.RWMutex{},
	}, nil
}

// Check checks if the user can perform the action on the resource
func (r *RBAC) Check(ctx context.Context, userID, resource, action string) bool {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	// Check if allowed
	allowed, err := r.enforcer.Enforce(userID, resource, action)
	if err != nil {
		// Log the error and deny access on error
		return false
	}

	return allowed
}

// AddUserRole adds a role to a user
func (r *RBAC) AddUserRole(userID string, role string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	_, err := r.enforcer.AddGroupingPolicy(userID, role)
	return err
}

// AddUserToOrg adds a user to an organization with a specific role
func (r *RBAC) AddUserToOrg(userID, orgID, role string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Format: g2, user123, org123:admin
	_, err := r.enforcer.AddNamedGroupingPolicy("g2", userID, fmt.Sprintf("%s:%s", orgID, role))
	return err
}

// RemoveUserRole removes a role from a user
func (r *RBAC) RemoveUserRole(userID string, role string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	_, err := r.enforcer.RemoveGroupingPolicy(userID, role)
	return err
}

// AddPolicy adds a policy rule
func (r *RBAC) AddPolicy(role, resource, action string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	_, err := r.enforcer.AddPolicy(role, resource, action)
	return err
}

// RemovePolicy removes a policy rule
func (r *RBAC) RemovePolicy(role, resource, action string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	_, err := r.enforcer.RemovePolicy(role, resource, action)
	return err
}

// GetUserRoles gets all roles for a user
func (r *RBAC) GetUserRoles(userID string) []string {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	roles, _ := r.enforcer.GetRolesForUser(userID)
	return roles
}

// LoadUserPermissions loads user permissions based on the User model
func (r *RBAC) LoadUserPermissions(user *models.User) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	userID := user.ID.String()

	// Clear existing user roles
	r.enforcer.RemoveFilteredGroupingPolicy(0, userID)

	// Add base role
	_, err := r.enforcer.AddGroupingPolicy(userID, string(user.Role))
	if err != nil {
		return fmt.Errorf("failed to add user role: %w", err)
	}

	// If super admin, add special role
	if user.OrgSuperAdmin {
		_, err = r.enforcer.AddNamedGroupingPolicy("g2", userID, "super_admin")
		if err != nil {
			return fmt.Errorf("failed to add super admin role: %w", err)
		}
	}

	// Add organization-specific role
	orgRole := fmt.Sprintf("%s:%s", user.OrganizationID.String(), string(user.Role))
	_, err = r.enforcer.AddNamedGroupingPolicy("g2", userID, orgRole)
	if err != nil {
		return fmt.Errorf("failed to add organization role: %w", err)
	}

	// For super admins, add access to all managed organizations
	if user.IsSuperAdmin() && len(user.ManagedOrgIDs) > 0 {
		for _, orgID := range user.ManagedOrgIDs {
			orgRole := fmt.Sprintf("%s:admin", orgID.String())
			_, err = r.enforcer.AddNamedGroupingPolicy("g2", userID, orgRole)
			if err != nil {
				return fmt.Errorf("failed to add managed organization role: %w", err)
			}
		}
	}

	return nil
}

// CreateUserContext creates a context that includes user information for authorization
func (r *RBAC) CreateUserContext(ctx context.Context, userID uuid.UUID) context.Context {
	return context.WithValue(ctx, "user_id", userID.String())
}

// GetUserFromContext extracts the user ID from context
func (r *RBAC) GetUserFromContext(ctx context.Context) (string, bool) {
	if userID, ok := ctx.Value("user_id").(string); ok {
		return userID, true
	}
	return "", false
}

// CanAccessOrganization checks if a user can access a specific organization
func (r *RBAC) CanAccessOrganization(ctx context.Context, userID string, orgID string) bool {
	// Format the resource as "organization:id"
	resource := fmt.Sprintf("organization:%s", orgID)
	return r.Check(ctx, userID, resource, "access")
}

// CanManageUsers checks if a user can manage users within an organization
func (r *RBAC) CanManageUsers(ctx context.Context, userID string, orgID string) bool {
	resource := fmt.Sprintf("users:%s", orgID)
	return r.Check(ctx, userID, resource, "manage")
}

// Memory adapter implements the persist.Adapter interface
type memoryAdapter struct {
	policies [][]string
}

func newMemoryAdapter() *memoryAdapter {
	return &memoryAdapter{
		policies: make([][]string, 0),
	}
}

func (a *memoryAdapter) LoadPolicy(model model.Model) error {
	for _, policy := range a.policies {
		persistPolicy(policy, model)
	}
	return nil
}

func (a *memoryAdapter) SavePolicy(model model.Model) error {
	a.policies = make([][]string, 0)

	// Save role definition section
	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			a.policies = append(a.policies, append([]string{ptype}, rule...))
		}
	}

	// Save policy definition section
	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			a.policies = append(a.policies, append([]string{ptype}, rule...))
		}
	}

	return nil
}

func (a *memoryAdapter) AddPolicy(sec string, ptype string, rule []string) error {
	a.policies = append(a.policies, append([]string{ptype}, rule...))
	return nil
}

func (a *memoryAdapter) RemovePolicy(sec string, ptype string, rule []string) error {
	for i, p := range a.policies {
		if p[0] == ptype && isEqual(p[1:], rule) {
			a.policies = append(a.policies[:i], a.policies[i+1:]...)
			return nil
		}
	}
	return nil
}

func (a *memoryAdapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	for i := 0; i < len(a.policies); i++ {
		p := a.policies[i]
		if p[0] == ptype && matchPolicy(p[1:], fieldIndex, fieldValues) {
			a.policies = append(a.policies[:i], a.policies[i+1:]...)
			i--
		}
	}
	return nil
}

func matchPolicy(policy []string, fieldIndex int, fieldValues []string) bool {
	if fieldIndex+len(fieldValues) > len(policy) {
		return false
	}

	for i, v := range fieldValues {
		if v != "" && policy[fieldIndex+i] != v {
			return false
		}
	}
	return true
}

func isEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

func persistPolicy(policy []string, model model.Model) {
	if len(policy) == 0 {
		return
	}
	ptype := policy[0]
	rule := policy[1:]

	switch ptype {
	case "p":
		model.AddPolicy("p", "p", rule)
	case "g":
		model.AddPolicy("g", "g", rule)
	case "g2":
		model.AddPolicy("g", "g2", rule)
	}
}

// Initialize default RBAC policies
func initializeDefaultPolicies(enforcer *casbin.Enforcer) {
	// Basic access policies for roles
	enforcer.AddPolicy("super_admin", "*", "*")

	// Organization admin policies
	enforcer.AddPolicy("admin", "organization", "access")
	enforcer.AddPolicy("admin", "organization", "manage")
	enforcer.AddPolicy("admin", "users", "view")
	enforcer.AddPolicy("admin", "users", "manage")
	enforcer.AddPolicy("admin", "teams", "view")
	enforcer.AddPolicy("admin", "teams", "manage")
	enforcer.AddPolicy("admin", "settings", "view")
	enforcer.AddPolicy("admin", "settings", "manage")
	enforcer.AddPolicy("admin", "audit", "view")

	// Manager policies
	enforcer.AddPolicy("manager", "organization", "access")
	enforcer.AddPolicy("manager", "users", "view")
	enforcer.AddPolicy("manager", "teams", "view")
	enforcer.AddPolicy("manager", "teams", "manage")
	enforcer.AddPolicy("manager", "settings", "view")
	enforcer.AddPolicy("manager", "audit", "view")

	// Regular user policies
	enforcer.AddPolicy("user", "organization", "access")
	enforcer.AddPolicy("user", "teams", "view")
	enforcer.AddPolicy("user", "user-profile", "manage")

	// Read-only user policies
	enforcer.AddPolicy("readonly", "organization", "access")
	enforcer.AddPolicy("readonly", "users", "view")
	enforcer.AddPolicy("readonly", "teams", "view")
}
