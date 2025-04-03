package consent

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// ConsentPurpose defines the purpose for which consent is given
type ConsentPurpose string

// Common consent purposes
const (
	PurposeDataProcessing  ConsentPurpose = "data_processing"   // General data processing
	PurposeMarketing       ConsentPurpose = "marketing"         // Marketing communications
	PurposeAnalytics       ConsentPurpose = "analytics"         // Analytics and improvement
	PurposeThirdPartyShare ConsentPurpose = "third_party_share" // Sharing with third parties
	PurposeProfiling       ConsentPurpose = "profiling"         // User profiling activities
	PurposeLocationData    ConsentPurpose = "location_data"     // Location data processing
	PurposeCookies         ConsentPurpose = "cookies"           // Cookie usage
	PurposeSensitiveData   ConsentPurpose = "sensitive_data"    // Processing sensitive data
)

// ConsentStatus represents the status of a consent record
type ConsentStatus string

// Consent statuses
const (
	StatusActive    ConsentStatus = "active"    // Consent is active
	StatusWithdrawn ConsentStatus = "withdrawn" // Consent has been withdrawn
	StatusExpired   ConsentStatus = "expired"   // Consent has expired
	StatusPending   ConsentStatus = "pending"   // Consent is pending
)

// ConsentRecord represents a record of user consent
type ConsentRecord struct {
	ID               string            `json:"id"`
	UserID           string            `json:"user_id"`
	TenantID         string            `json:"tenant_id"`
	Purpose          ConsentPurpose    `json:"purpose"`
	Status           ConsentStatus     `json:"status"`
	ConsentText      string            `json:"consent_text"`
	ConsentVersion   string            `json:"consent_version"`
	PrivacyPolicyURL string            `json:"privacy_policy_url"`
	DataCategories   []string          `json:"data_categories"`
	GrantedAt        time.Time         `json:"granted_at"`
	ExpiresAt        *time.Time        `json:"expires_at,omitempty"`
	WithdrawnAt      *time.Time        `json:"withdrawn_at,omitempty"`
	ProofOfConsent   string            `json:"proof_of_consent"`
	ClientIPAddress  string            `json:"client_ip_address"`
	UserAgent        string            `json:"user_agent"`
	ConsentMethod    string            `json:"consent_method"` // How consent was collected
	LegalBasis       string            `json:"legal_basis"`
	AdditionalInfo   map[string]string `json:"additional_info,omitempty"`
	History          []ConsentEvent    `json:"history,omitempty"`
}

// ConsentEvent represents an event in the consent lifecycle
type ConsentEvent struct {
	Timestamp      time.Time     `json:"timestamp"`
	Action         string        `json:"action"`
	PreviousStatus ConsentStatus `json:"previous_status"`
	NewStatus      ConsentStatus `json:"new_status"`
	Reason         string        `json:"reason,omitempty"`
	PerformedBy    string        `json:"performed_by"` // User ID or system
	IPAddress      string        `json:"ip_address,omitempty"`
}

// ConsentStorage defines the interface for consent storage
type ConsentStorage interface {
	StoreConsent(record ConsentRecord) error
	GetConsent(id string) (ConsentRecord, error)
	GetUserConsents(userID string) ([]ConsentRecord, error)
	GetUserConsentForPurpose(userID string, purpose ConsentPurpose) (ConsentRecord, error)
	UpdateConsent(record ConsentRecord) error
	WithdrawConsent(id string, withdrawalInfo ConsentEvent) error
	ListActivePurposes(userID string) ([]ConsentPurpose, error)
}

// ConsentManager manages user consents
type ConsentManager struct {
	storage   ConsentStorage
	templates map[ConsentPurpose]ConsentTemplate
}

// ConsentTemplate is a template for consent records
type ConsentTemplate struct {
	Purpose          ConsentPurpose `json:"purpose"`
	Version          string         `json:"version"`
	ConsentText      string         `json:"consent_text"`
	PrivacyPolicyURL string         `json:"privacy_policy_url"`
	DataCategories   []string       `json:"data_categories"`
	LegalBasis       string         `json:"legal_basis"`
	Duration         time.Duration  `json:"duration,omitempty"` // How long consent lasts
	RequiresExplicit bool           `json:"requires_explicit"`  // Requires explicit opt-in
}

// Errors
var (
	ErrConsentNotFound         = errors.New("consent record not found")
	ErrConsentAlreadyExists    = errors.New("consent already exists")
	ErrInvalidConsentPurpose   = errors.New("invalid consent purpose")
	ErrInvalidConsentStatus    = errors.New("invalid consent status")
	ErrConsentAlreadyWithdrawn = errors.New("consent already withdrawn")
	ErrConsentExpired          = errors.New("consent has expired")
	ErrInsufficientConsent     = errors.New("insufficient consent for requested operation")
)

// NewConsentManager creates a new consent manager
func NewConsentManager(storage ConsentStorage) *ConsentManager {
	return &ConsentManager{
		storage:   storage,
		templates: make(map[ConsentPurpose]ConsentTemplate),
	}
}

// RegisterTemplate registers a consent template
func (m *ConsentManager) RegisterTemplate(template ConsentTemplate) {
	m.templates[template.Purpose] = template
}

// CreateConsent creates a new consent record
func (m *ConsentManager) CreateConsent(
	userID string,
	tenantID string,
	purpose ConsentPurpose,
	clientIP string,
	userAgent string,
	additionalInfo map[string]string,
) (ConsentRecord, error) {
	// Check if template exists
	template, exists := m.templates[purpose]
	if !exists {
		return ConsentRecord{}, ErrInvalidConsentPurpose
	}

	// Check if consent already exists and is active
	existingConsent, err := m.storage.GetUserConsentForPurpose(userID, purpose)
	if err == nil && existingConsent.Status == StatusActive {
		return ConsentRecord{}, ErrConsentAlreadyExists
	}

	// Create new consent record
	now := time.Now()
	var expiresAt *time.Time
	if template.Duration > 0 {
		expiry := now.Add(template.Duration)
		expiresAt = &expiry
	}

	record := ConsentRecord{
		ID:               uuid.New().String(),
		UserID:           userID,
		TenantID:         tenantID,
		Purpose:          purpose,
		Status:           StatusActive,
		ConsentText:      template.ConsentText,
		ConsentVersion:   template.Version,
		PrivacyPolicyURL: template.PrivacyPolicyURL,
		DataCategories:   template.DataCategories,
		GrantedAt:        now,
		ExpiresAt:        expiresAt,
		ClientIPAddress:  clientIP,
		UserAgent:        userAgent,
		ConsentMethod:    "api", // Default method
		LegalBasis:       template.LegalBasis,
		AdditionalInfo:   additionalInfo,
		History: []ConsentEvent{
			{
				Timestamp:      now,
				Action:         "grant",
				PreviousStatus: "",
				NewStatus:      StatusActive,
				PerformedBy:    userID,
				IPAddress:      clientIP,
			},
		},
	}

	// Store consent record
	if err := m.storage.StoreConsent(record); err != nil {
		return ConsentRecord{}, err
	}

	return record, nil
}

// WithdrawConsent withdraws a consent
func (m *ConsentManager) WithdrawConsent(
	consentID string,
	reason string,
	performedBy string,
	clientIP string,
) error {
	// Get consent record
	consent, err := m.storage.GetConsent(consentID)
	if err != nil {
		return ErrConsentNotFound
	}

	// Check if consent is already withdrawn
	if consent.Status == StatusWithdrawn {
		return ErrConsentAlreadyWithdrawn
	}

	// Create withdrawal event
	now := time.Now()
	event := ConsentEvent{
		Timestamp:      now,
		Action:         "withdraw",
		PreviousStatus: consent.Status,
		NewStatus:      StatusWithdrawn,
		Reason:         reason,
		PerformedBy:    performedBy,
		IPAddress:      clientIP,
	}

	// Update consent record
	return m.storage.WithdrawConsent(consentID, event)
}

// HasActiveConsent checks if user has active consent for a purpose
func (m *ConsentManager) HasActiveConsent(userID string, purpose ConsentPurpose) (bool, error) {
	// Get consent for the purpose
	consent, err := m.storage.GetUserConsentForPurpose(userID, purpose)
	if err != nil {
		if err == ErrConsentNotFound {
			return false, nil
		}
		return false, err
	}

	// Check if consent is active
	if consent.Status != StatusActive {
		return false, nil
	}

	// Check if consent has expired
	if consent.ExpiresAt != nil && time.Now().After(*consent.ExpiresAt) {
		// Update status to expired
		event := ConsentEvent{
			Timestamp:      time.Now(),
			Action:         "expire",
			PreviousStatus: consent.Status,
			NewStatus:      StatusExpired,
			Reason:         "Consent expired",
			PerformedBy:    "system",
		}
		consent.Status = StatusExpired
		consent.History = append(consent.History, event)
		m.storage.UpdateConsent(consent)
		return false, nil
	}

	return true, nil
}

// GetActivePurposes gets all active consent purposes for a user
func (m *ConsentManager) GetActivePurposes(userID string) ([]ConsentPurpose, error) {
	return m.storage.ListActivePurposes(userID)
}

// RequireConsent ensures a user has consent for a specific purpose
func (m *ConsentManager) RequireConsent(userID string, purpose ConsentPurpose) error {
	hasConsent, err := m.HasActiveConsent(userID, purpose)
	if err != nil {
		return err
	}

	if !hasConsent {
		return ErrInsufficientConsent
	}

	return nil
}

// GetUserConsents gets all consent records for a user
func (m *ConsentManager) GetUserConsents(userID string) ([]ConsentRecord, error) {
	return m.storage.GetUserConsents(userID)
}

// GetConsentRecord gets a specific consent record
func (m *ConsentManager) GetConsentRecord(consentID string) (ConsentRecord, error) {
	return m.storage.GetConsent(consentID)
}
