package api

import (
	"fmt"
	"net/http"

	"gobackend/internal/models"
	"gobackend/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// TeamHandlers handles team-related API endpoints
type TeamHandlers struct {
	teamService *services.TeamService
}

// NewTeamHandlers creates a new team handlers instance
func NewTeamHandlers(teamService *services.TeamService) *TeamHandlers {
	return &TeamHandlers{
		teamService: teamService,
	}
}

// CreateTeamRequest represents a request to create a team
type CreateTeamRequest struct {
	Name           string    `json:"name" binding:"required"`
	Description    string    `json:"description"`
	OrganizationID uuid.UUID `json:"organizationId" binding:"required"`
}

// GetPaginationParams extracts pagination parameters from the request
func GetPaginationParams(c *gin.Context) (int, int) {
	// Default page and size
	page := 1
	size := 20

	// Parse page parameter
	if pageParam := c.Query("page"); pageParam != "" {
		if parsedPage, err := parseInt(pageParam); err == nil && parsedPage > 0 {
			page = parsedPage
		}
	}

	// Parse size parameter
	if sizeParam := c.Query("size"); sizeParam != "" {
		if parsedSize, err := parseInt(sizeParam); err == nil && parsedSize > 0 && parsedSize <= 100 {
			size = parsedSize
		}
	}

	return page, size
}

// parseInt helper to parse string to int
func parseInt(value string) (int, error) {
	var parsedValue int
	_, err := fmt.Sscanf(value, "%d", &parsedValue)
	return parsedValue, err
}

// ListTeams godoc
// @Summary List teams
// @Description Get a list of all teams the user has access to
// @Tags teams
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {array} models.Team
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 403 {object} map[string]string "Forbidden"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/teams [get]
func (h *TeamHandlers) ListTeams(c *gin.Context) {
	// Get the current user from context
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}
	currentUser := user.(*models.User)

	// Parse pagination parameters
	page, size := GetPaginationParams(c)

	// Get organization filter if provided
	organizationIDStr := c.Query("organization_id")
	var organizationID uuid.UUID
	if organizationIDStr != "" {
		var err error
		organizationID, err = uuid.Parse(organizationIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid organization ID"})
			return
		}
	}

	// Get teams
	teams, total, err := h.teamService.ListTeams(currentUser.ID, organizationID, page, size)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": teams,
		"meta": gin.H{
			"total": total,
			"page":  page,
			"size":  size,
		},
	})
}

// GetTeam godoc
// @Summary Get team
// @Description Get a specific team by ID
// @Tags teams
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Team ID"
// @Success 200 {object} models.Team
// @Failure 400 {object} map[string]string "Bad request"
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 403 {object} map[string]string "Forbidden"
// @Failure 404 {object} map[string]string "Team not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/teams/{id} [get]
func (h *TeamHandlers) GetTeam(c *gin.Context) {
	// Parse team ID from URL
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid team ID"})
		return
	}

	// Get the team
	team, err := h.teamService.GetTeam(id)
	if err != nil {
		if err.Error() == "team not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Team not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	c.JSON(http.StatusOK, team)
}

// CreateTeam godoc
// @Summary Create team
// @Description Create a new team
// @Tags teams
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param team body CreateTeamRequest true "Team to create"
// @Success 201 {object} models.Team
// @Failure 400 {object} map[string]string "Bad request"
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 403 {object} map[string]string "Forbidden"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/teams [post]
func (h *TeamHandlers) CreateTeam(c *gin.Context) {
	// Get the current user from context
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}
	currentUser := user.(*models.User)

	// Parse request body
	var request CreateTeamRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Create team model from request
	team := &models.Team{
		Name:           request.Name,
		Description:    request.Description,
		OrganizationID: request.OrganizationID,
	}

	// Create the team
	createdTeam, err := h.teamService.CreateTeam(team, currentUser.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, createdTeam)
}

// UpdateTeamRequest represents a request to update a team
type UpdateTeamRequest struct {
	Name        string `json:"name" binding:"required"`
	Description string `json:"description"`
}

// UpdateTeam godoc
// @Summary Update team
// @Description Update an existing team
// @Tags teams
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Team ID"
// @Param team body UpdateTeamRequest true "Updated team"
// @Success 200 {object} models.Team
// @Failure 400 {object} map[string]string "Bad request"
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 403 {object} map[string]string "Forbidden"
// @Failure 404 {object} map[string]string "Team not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/teams/{id} [put]
func (h *TeamHandlers) UpdateTeam(c *gin.Context) {
	// Parse team ID from URL
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid team ID"})
		return
	}

	// Parse request body
	var request UpdateTeamRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	team := &models.Team{
		ID:          id,
		Name:        request.Name,
		Description: request.Description,
	}

	// Update the team
	updatedTeam, err := h.teamService.UpdateTeam(team)
	if err != nil {
		if err.Error() == "team not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Team not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	c.JSON(http.StatusOK, updatedTeam)
}

// DeleteTeam godoc
// @Summary Delete team
// @Description Delete a team
// @Tags teams
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Team ID"
// @Success 200 {object} map[string]string "Success message"
// @Failure 400 {object} map[string]string "Bad request"
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 403 {object} map[string]string "Forbidden"
// @Failure 404 {object} map[string]string "Team not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/teams/{id} [delete]
func (h *TeamHandlers) DeleteTeam(c *gin.Context) {
	// Parse team ID from URL
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid team ID"})
		return
	}

	// Delete the team
	err = h.teamService.DeleteTeam(id)
	if err != nil {
		if err.Error() == "team not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Team not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Team deleted successfully"})
}

// TeamMemberRequest represents a request to add a team member
type TeamMemberRequest struct {
	UserID uuid.UUID `json:"userId" binding:"required"`
	Role   string    `json:"role" binding:"required"`
}

// ListTeamMembers godoc
// @Summary List team members
// @Description Get a list of all members of a team
// @Tags teams
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Team ID"
// @Success 200 {array} models.User
// @Failure 400 {object} map[string]string "Bad request"
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 403 {object} map[string]string "Forbidden"
// @Failure 404 {object} map[string]string "Team not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/teams/{id}/members [get]
func (h *TeamHandlers) ListTeamMembers(c *gin.Context) {
	// Parse team ID from URL
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid team ID"})
		return
	}

	// Parse pagination parameters
	page, size := GetPaginationParams(c)

	// Get team members
	members, total, err := h.teamService.ListTeamMembers(id, page, size)
	if err != nil {
		if err.Error() == "team not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Team not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": members,
		"meta": gin.H{
			"total": total,
			"page":  page,
			"size":  size,
		},
	})
}

// AddTeamMember godoc
// @Summary Add team member
// @Description Add a user as a member to a team
// @Tags teams
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Team ID"
// @Param member body TeamMemberRequest true "Team member to add"
// @Success 200 {object} map[string]string "Success message"
// @Failure 400 {object} map[string]string "Bad request"
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 403 {object} map[string]string "Forbidden"
// @Failure 404 {object} map[string]string "Team not found"
// @Failure 409 {object} map[string]string "User is already a team member"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/teams/{id}/members [post]
func (h *TeamHandlers) AddTeamMember(c *gin.Context) {
	// Parse team ID from URL
	idStr := c.Param("id")
	teamID, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid team ID"})
		return
	}

	// Parse request body
	var req TeamMemberRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Add the member
	err = h.teamService.AddTeamMember(teamID, req.UserID, req.Role)
	if err != nil {
		if err.Error() == "team not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Team not found"})
		} else if err.Error() == "user not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		} else if err.Error() == "user is already a member of this team" {
			c.JSON(http.StatusConflict, gin.H{"error": "User is already a member of this team"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User added to team successfully"})
}

// RemoveTeamMember godoc
// @Summary Remove team member
// @Description Remove a user from a team
// @Tags teams
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Team ID"
// @Param userId path string true "User ID"
// @Success 200 {object} map[string]string "Success message"
// @Failure 400 {object} map[string]string "Bad request"
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 403 {object} map[string]string "Forbidden"
// @Failure 404 {object} map[string]string "Team or user not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/teams/{id}/members/{userId} [delete]
func (h *TeamHandlers) RemoveTeamMember(c *gin.Context) {
	// Parse team ID from URL
	idStr := c.Param("id")
	teamID, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid team ID"})
		return
	}

	// Parse user ID from URL
	userIDStr := c.Param("userId")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	// Remove the member
	err = h.teamService.RemoveTeamMember(teamID, userID)
	if err != nil {
		if err.Error() == "team not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Team not found"})
		} else if err.Error() == "user not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		} else if err.Error() == "user is not a member of this team" {
			c.JSON(http.StatusNotFound, gin.H{"error": "User is not a member of this team"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User removed from team successfully"})
}
