package api

import (
	"net/http"
	"strconv"
	"time"

	"gobackend/internal/models"
	"gobackend/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// OrganizationResponse represents the organization response
type OrganizationResponse struct {
	ID             uuid.UUID          `json:"id"`
	Name           string             `json:"name"`
	DisplayName    string             `json:"displayName"`
	Industry       string             `json:"industry,omitempty"`
	Website        string             `json:"website,omitempty"`
	Logo           string             `json:"logo,omitempty"`
	Address        models.Address     `json:"address,omitempty"`
	ContactEmail   string             `json:"contactEmail"`
	ContactPhone   string             `json:"contactPhone,omitempty"`
	PrimaryDomain  string             `json:"primaryDomain"`
	AllowedDomains []string           `json:"allowedDomains,omitempty"`
	Status         string             `json:"status"`
	Settings       models.OrgSettings `json:"settings,omitempty"`
	MaxUsers       int                `json:"maxUsers"`
	TenantID       uuid.UUID          `json:"tenantId"`
	CreatedAt      string             `json:"createdAt"`
	UpdatedAt      string             `json:"updatedAt"`
}

// CreateOrganizationRequest represents the request to create an organization
type CreateOrganizationRequest struct {
	Name           string             `json:"name" binding:"required"`
	DisplayName    string             `json:"displayName" binding:"required"`
	Industry       string             `json:"industry,omitempty"`
	Website        string             `json:"website,omitempty"`
	Logo           string             `json:"logo,omitempty"`
	Address        models.Address     `json:"address,omitempty"`
	ContactEmail   string             `json:"contactEmail" binding:"required,email"`
	ContactPhone   string             `json:"contactPhone,omitempty"`
	PrimaryDomain  string             `json:"primaryDomain" binding:"required"`
	AllowedDomains []string           `json:"allowedDomains,omitempty"`
	Settings       models.OrgSettings `json:"settings,omitempty"`
	MaxUsers       int                `json:"maxUsers,omitempty"`
	TenantID       uuid.UUID          `json:"tenantId" binding:"required"`
}

// UpdateOrganizationRequest represents the request to update an organization
type UpdateOrganizationRequest struct {
	Name           string             `json:"name" binding:"required"`
	DisplayName    string             `json:"displayName" binding:"required"`
	Industry       string             `json:"industry,omitempty"`
	Website        string             `json:"website,omitempty"`
	Logo           string             `json:"logo,omitempty"`
	Address        models.Address     `json:"address,omitempty"`
	ContactEmail   string             `json:"contactEmail" binding:"required,email"`
	ContactPhone   string             `json:"contactPhone,omitempty"`
	PrimaryDomain  string             `json:"primaryDomain" binding:"required"`
	AllowedDomains []string           `json:"allowedDomains,omitempty"`
	Status         string             `json:"status,omitempty"`
	Settings       models.OrgSettings `json:"settings,omitempty"`
	MaxUsers       int                `json:"maxUsers,omitempty"`
}

// PaginatedOrganizationsResponse represents a paginated list of organizations
type PaginatedOrganizationsResponse struct {
	Items      []OrganizationResponse `json:"items"`
	TotalCount int                    `json:"totalCount"`
	Page       int                    `json:"page"`
	PageSize   int                    `json:"pageSize"`
}

// OrganizationHandlers contains handlers for organization endpoints
type OrganizationHandlers struct {
	service *services.OrganizationService
}

// NewOrganizationHandlers creates a new organization handlers
func NewOrganizationHandlers(service *services.OrganizationService) *OrganizationHandlers {
	return &OrganizationHandlers{
		service: service,
	}
}

// @Summary Get a list of organizations
// @Description Get a paginated list of organizations
// @Tags organizations
// @Accept json
// @Produce json
// @Param page query int false "Page number (default: 1)"
// @Param page_size query int false "Page size (default: 20, max: 100)"
// @Success 200 {object} PaginatedOrganizationsResponse
// @Failure 400 {object} ResponseError
// @Failure 401 {object} ResponseError
// @Failure 500 {object} ResponseError
// @Security BearerAuth
// @Router /api/v1/organizations [get]
func (h *OrganizationHandlers) ListOrganizations(c *gin.Context) {
	// Parse pagination parameters manually
	pageStr := c.DefaultQuery("page", "1")
	pageSizeStr := c.DefaultQuery("page_size", "20")

	// Set defaults
	page := 1
	pageSize := 20

	// Convert to integers
	if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
		page = p
	}

	if ps, err := strconv.Atoi(pageSizeStr); err == nil && ps > 0 && ps <= 100 {
		pageSize = ps
	}

	// Call service to list organizations
	orgs, total, err := h.service.List(c.Request.Context(), page, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ResponseError{
			Error: "Failed to retrieve organizations: " + err.Error(),
		})
		return
	}

	// Create response
	response := PaginatedOrganizationsResponse{
		Items:      make([]OrganizationResponse, 0, len(orgs)),
		TotalCount: total,
		Page:       page,
		PageSize:   pageSize,
	}

	// Map organizations to response objects
	for _, org := range orgs {
		response.Items = append(response.Items, mapOrganizationToResponse(org))
	}

	c.JSON(http.StatusOK, response)
}

// @Summary Get an organization by ID
// @Description Get detailed information about an organization
// @Tags organizations
// @Accept json
// @Produce json
// @Param id path string true "Organization ID" format(uuid)
// @Success 200 {object} OrganizationResponse
// @Failure 400 {object} ResponseError
// @Failure 401 {object} ResponseError
// @Failure 404 {object} ResponseError
// @Failure 500 {object} ResponseError
// @Security BearerAuth
// @Router /api/v1/organizations/{id} [get]
func (h *OrganizationHandlers) GetOrganization(c *gin.Context) {
	// Parse ID from path
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, ResponseError{
			Error: "Invalid organization ID",
		})
		return
	}

	// Call service to get organization
	org, err := h.service.GetByID(c.Request.Context(), id)
	if err != nil {
		status := http.StatusInternalServerError
		if err.Error() == "record not found" {
			status = http.StatusNotFound
		}
		c.JSON(status, ResponseError{
			Error: "Failed to retrieve organization: " + err.Error(),
		})
		return
	}

	// Map to response and return
	c.JSON(http.StatusOK, mapOrganizationToResponse(org))
}

// @Summary Create a new organization
// @Description Create a new organization
// @Tags organizations
// @Accept json
// @Produce json
// @Param organization body CreateOrganizationRequest true "Organization to create"
// @Success 201 {object} OrganizationResponse
// @Failure 400 {object} ResponseError
// @Failure 401 {object} ResponseError
// @Failure 409 {object} ResponseError
// @Failure 500 {object} ResponseError
// @Security BearerAuth
// @Router /api/v1/organizations [post]
func (h *OrganizationHandlers) CreateOrganization(c *gin.Context) {
	var req CreateOrganizationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ResponseError{
			Error: "Invalid request: " + err.Error(),
		})
		return
	}

	// Map request to model
	org := &models.Organization{
		Name:           req.Name,
		DisplayName:    req.DisplayName,
		Industry:       req.Industry,
		Website:        req.Website,
		Logo:           req.Logo,
		Address:        req.Address,
		ContactEmail:   req.ContactEmail,
		ContactPhone:   req.ContactPhone,
		PrimaryDomain:  req.PrimaryDomain,
		AllowedDomains: req.AllowedDomains,
		Settings:       req.Settings,
		MaxUsers:       req.MaxUsers,
		TenantID:       req.TenantID,
	}

	// Call service to create organization
	createdOrg, err := h.service.Create(c.Request.Context(), org)
	if err != nil {
		status := http.StatusInternalServerError

		// Check for duplicate error
		if err.Error() == "an organization with this primary domain already exists" {
			status = http.StatusConflict
		} else if err.Error() == "name is required" ||
			err.Error() == "display name is required" ||
			err.Error() == "primary domain is required" ||
			err.Error() == "contact email is required" ||
			err.Error() == "tenant ID is required" {
			status = http.StatusBadRequest
		}

		c.JSON(status, ResponseError{
			Error: "Failed to create organization: " + err.Error(),
		})
		return
	}

	// Map to response and return
	c.JSON(http.StatusCreated, mapOrganizationToResponse(createdOrg))
}

// @Summary Update an organization
// @Description Update an existing organization
// @Tags organizations
// @Accept json
// @Produce json
// @Param id path string true "Organization ID" format(uuid)
// @Param organization body UpdateOrganizationRequest true "Organization data to update"
// @Success 200 {object} OrganizationResponse
// @Failure 400 {object} ResponseError
// @Failure 401 {object} ResponseError
// @Failure 404 {object} ResponseError
// @Failure 409 {object} ResponseError
// @Failure 500 {object} ResponseError
// @Security BearerAuth
// @Router /api/v1/organizations/{id} [put]
func (h *OrganizationHandlers) UpdateOrganization(c *gin.Context) {
	// Parse ID from path
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, ResponseError{
			Error: "Invalid organization ID",
		})
		return
	}

	var req UpdateOrganizationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ResponseError{
			Error: "Invalid request: " + err.Error(),
		})
		return
	}

	// Map request to model
	org := &models.Organization{
		ID:             id,
		Name:           req.Name,
		DisplayName:    req.DisplayName,
		Industry:       req.Industry,
		Website:        req.Website,
		Logo:           req.Logo,
		Address:        req.Address,
		ContactEmail:   req.ContactEmail,
		ContactPhone:   req.ContactPhone,
		PrimaryDomain:  req.PrimaryDomain,
		AllowedDomains: req.AllowedDomains,
		Status:         models.OrgStatus(req.Status),
		Settings:       req.Settings,
		MaxUsers:       req.MaxUsers,
	}

	// Call service to update organization
	updatedOrg, err := h.service.Update(c.Request.Context(), org)
	if err != nil {
		status := http.StatusInternalServerError

		// Check for specific errors
		if err.Error() == "record not found" {
			status = http.StatusNotFound
		} else if err.Error() == "an organization with this primary domain already exists" {
			status = http.StatusConflict
		} else if err.Error() == "name is required" ||
			err.Error() == "display name is required" ||
			err.Error() == "primary domain is required" ||
			err.Error() == "contact email is required" ||
			err.Error() == "organization ID is required" {
			status = http.StatusBadRequest
		}

		c.JSON(status, ResponseError{
			Error: "Failed to update organization: " + err.Error(),
		})
		return
	}

	// Map to response and return
	c.JSON(http.StatusOK, mapOrganizationToResponse(updatedOrg))
}

// @Summary Delete an organization
// @Description Delete an organization by ID
// @Tags organizations
// @Accept json
// @Produce json
// @Param id path string true "Organization ID" format(uuid)
// @Success 204 "No Content"
// @Failure 400 {object} ResponseError
// @Failure 401 {object} ResponseError
// @Failure 404 {object} ResponseError
// @Failure 500 {object} ResponseError
// @Security BearerAuth
// @Router /api/v1/organizations/{id} [delete]
func (h *OrganizationHandlers) DeleteOrganization(c *gin.Context) {
	// Parse ID from path
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, ResponseError{
			Error: "Invalid organization ID",
		})
		return
	}

	// Call service to delete organization
	err = h.service.Delete(c.Request.Context(), id)
	if err != nil {
		status := http.StatusInternalServerError

		// Check for not found error
		if err.Error() == "record not found" {
			status = http.StatusNotFound
		}

		c.JSON(status, ResponseError{
			Error: "Failed to delete organization: " + err.Error(),
		})
		return
	}

	c.Status(http.StatusNoContent)
}

// Helper function to map an organization model to a response
func mapOrganizationToResponse(org *models.Organization) OrganizationResponse {
	return OrganizationResponse{
		ID:             org.ID,
		Name:           org.Name,
		DisplayName:    org.DisplayName,
		Industry:       org.Industry,
		Website:        org.Website,
		Logo:           org.Logo,
		Address:        org.Address,
		ContactEmail:   org.ContactEmail,
		ContactPhone:   org.ContactPhone,
		PrimaryDomain:  org.PrimaryDomain,
		AllowedDomains: org.AllowedDomains,
		Status:         string(org.Status),
		Settings:       org.Settings,
		MaxUsers:       org.MaxUsers,
		TenantID:       org.TenantID,
		CreatedAt:      org.CreatedAt.Format(time.RFC3339),
		UpdatedAt:      org.UpdatedAt.Format(time.RFC3339),
	}
}
