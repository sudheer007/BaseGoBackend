package services

import (
	"errors"
	"time"

	"gobackend/internal/models"

	"github.com/go-pg/pg/v10"
	"github.com/google/uuid"
)

// TeamService handles business logic for team operations
type TeamService struct {
	DB *pg.DB
}

// NewTeamService creates a new TeamService
func NewTeamService(db *pg.DB) *TeamService {
	return &TeamService{
		DB: db,
	}
}

// ListTeams returns a list of teams the user has access to
func (s *TeamService) ListTeams(userID uuid.UUID, organizationID uuid.UUID, page, size int) ([]*models.Team, int, error) {
	offset := (page - 1) * size
	var teams []*models.Team

	query := s.DB.Model(&teams).
		Join("JOIN team_members AS tm ON tm.team_id = team.id").
		Where("tm.user_id = ?", userID)

	if organizationID != uuid.Nil {
		query = query.Where("team.organization_id = ?", organizationID)
	}

	total, err := query.
		Order("team.created_at DESC").
		Limit(size).
		Offset(offset).
		SelectAndCount()

	if err != nil {
		return nil, 0, err
	}

	return teams, total, nil
}

// GetTeam returns a team by ID
func (s *TeamService) GetTeam(id uuid.UUID) (*models.Team, error) {
	team := &models.Team{ID: id}
	err := s.DB.Model(team).
		WherePK().
		Select()

	if err != nil {
		if err == pg.ErrNoRows {
			return nil, errors.New("team not found")
		}
		return nil, err
	}

	return team, nil
}

// CreateTeam creates a new team
func (s *TeamService) CreateTeam(team *models.Team, creatorID uuid.UUID) (*models.Team, error) {
	err := s.DB.RunInTransaction(s.DB.Context(), func(tx *pg.Tx) error {
		// Set team defaults
		if team.ID == uuid.Nil {
			team.ID = uuid.New()
		}
		team.CreatedBy = creatorID
		team.Status = models.TeamStatusActive
		team.CreatedAt = time.Now()
		team.UpdatedAt = time.Now()

		// Insert team
		_, err := tx.Model(team).Insert()
		if err != nil {
			return err
		}

		// Add creator as team admin
		teamMember := &models.TeamMember{
			TeamID:    team.ID,
			UserID:    creatorID,
			Role:      "admin",
			CreatedAt: time.Now(),
		}

		_, err = tx.Model(teamMember).Insert()
		return err
	})

	if err != nil {
		return nil, err
	}

	// Get full team with updated fields
	return s.GetTeam(team.ID)
}

// UpdateTeam updates an existing team
func (s *TeamService) UpdateTeam(team *models.Team) (*models.Team, error) {
	// Check if team exists
	_, err := s.GetTeam(team.ID)
	if err != nil {
		return nil, err
	}

	// Update team
	team.UpdatedAt = time.Now()
	_, err = s.DB.Model(team).
		WherePK().
		Column("name", "description", "updated_at").
		Update()

	if err != nil {
		return nil, err
	}

	// Get updated team
	return s.GetTeam(team.ID)
}

// DeleteTeam deletes a team
func (s *TeamService) DeleteTeam(id uuid.UUID) error {
	// Check if team exists
	_, err := s.GetTeam(id)
	if err != nil {
		return err
	}

	err = s.DB.RunInTransaction(s.DB.Context(), func(tx *pg.Tx) error {
		// Delete team members
		_, err := tx.Model((*models.TeamMember)(nil)).
			Where("team_id = ?", id).
			Delete()
		if err != nil {
			return err
		}

		// Delete team
		_, err = tx.Model(&models.Team{ID: id}).WherePK().Delete()
		return err
	})

	return err
}

// ListTeamMembers lists all members of a team
func (s *TeamService) ListTeamMembers(teamID uuid.UUID, page, size int) ([]*models.TeamMember, int, error) {
	// Check if team exists
	_, err := s.GetTeam(teamID)
	if err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * size
	var members []*models.TeamMember

	total, err := s.DB.Model(&members).
		Where("team_id = ?", teamID).
		Relation("User").
		Order("created_at DESC").
		Limit(size).
		Offset(offset).
		SelectAndCount()

	if err != nil {
		return nil, 0, err
	}

	return members, total, nil
}

// AddTeamMember adds a user to a team
func (s *TeamService) AddTeamMember(teamID, userID uuid.UUID, role string) error {
	// Check if team exists
	_, err := s.GetTeam(teamID)
	if err != nil {
		return err
	}

	// Check if user exists
	exists, err := s.DB.Model((*models.User)(nil)).
		Where("id = ?", userID).
		Exists()
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("user not found")
	}

	// Check if user is already a member
	exists, err = s.DB.Model((*models.TeamMember)(nil)).
		Where("team_id = ? AND user_id = ?", teamID, userID).
		Exists()
	if err != nil {
		return err
	}
	if exists {
		return errors.New("user is already a member of this team")
	}

	// Add user to team
	member := &models.TeamMember{
		TeamID:    teamID,
		UserID:    userID,
		Role:      role,
		CreatedAt: time.Now(),
	}
	_, err = s.DB.Model(member).Insert()
	return err
}

// RemoveTeamMember removes a user from a team
func (s *TeamService) RemoveTeamMember(teamID, userID uuid.UUID) error {
	// Check if team exists
	_, err := s.GetTeam(teamID)
	if err != nil {
		return err
	}

	// Check if user is a member
	exists, err := s.DB.Model((*models.TeamMember)(nil)).
		Where("team_id = ? AND user_id = ?", teamID, userID).
		Exists()
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("user is not a member of this team")
	}

	// Remove user from team
	_, err = s.DB.Model((*models.TeamMember)(nil)).
		Where("team_id = ? AND user_id = ?", teamID, userID).
		Delete()
	return err
}
