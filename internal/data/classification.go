package data

import (
	"time"
)

// DataClassification represents a data sensitivity classification
type DataClassification string

// Data classifications
const (
	ClassificationPublic       DataClassification = "public"       // No restrictions on data access
	ClassificationInternal     DataClassification = "internal"     // Internal use only
	ClassificationConfidential DataClassification = "confidential" // Sensitive business data
	ClassificationSensitive    DataClassification = "sensitive"    // Sensitive personal data
	ClassificationRestricted   DataClassification = "restricted"   // Highly sensitive, regulated data
)

// DataCategory represents a category of data
type DataCategory string

// Data categories
const (
	CategoryPersonalData       DataCategory = "personal_data"       // Personal data (names, emails, etc.)
	CategoryFinancialData      DataCategory = "financial_data"      // Financial information
	CategoryHealthData         DataCategory = "health_data"         // Health-related information
	CategoryAuthenticationData DataCategory = "authentication_data" // Auth data (passwords, tokens)
	CategoryBusinessData       DataCategory = "business_data"       // Business information
	CategoryTransactionalData  DataCategory = "transactional_data"  // Transaction records
	CategoryMetadata           DataCategory = "metadata"            // Metadata about other data
	CategoryAuditData          DataCategory = "audit_data"          // Audit logs and records
)

// DataAttributes represents attributes used for classification and handling
type DataAttributes struct {
	Classification  DataClassification  `json:"classification"`
	Categories      []DataCategory      `json:"categories"`
	Encrypted       bool                `json:"encrypted"`
	PII             bool                `json:"pii"`  // Personally Identifiable Information
	PHI             bool                `json:"phi"`  // Protected Health Information
	PCI             bool                `json:"pci"`  // Payment Card Information
	GDPR            bool                `json:"gdpr"` // Subject to GDPR
	CCPA            bool                `json:"ccpa"` // Subject to CCPA
	RetentionPolicy RetentionPolicyType `json:"retention_policy"`
	RetentionDate   time.Time           `json:"retention_date"`
	Tags            map[string]string   `json:"tags"`
	Jurisdiction    string              `json:"jurisdiction"`
	DataOwner       string              `json:"data_owner"`
	CreatedAt       time.Time           `json:"created_at"`
	UpdatedAt       time.Time           `json:"updated_at"`
	AccessHistory   []DataAccessRecord  `json:"access_history,omitempty"`
}

// RetentionPolicyType defines a data retention policy
type RetentionPolicyType string

// Retention policies
const (
	RetentionIndefinite RetentionPolicyType = "indefinite" // No automatic deletion
	RetentionTransient  RetentionPolicyType = "transient"  // Very short-term (e.g., session)
	RetentionShortTerm  RetentionPolicyType = "short_term" // Short-term (e.g., 30 days)
	RetentionStandard   RetentionPolicyType = "standard"   // Standard retention (e.g., 1 year)
	RetentionLongTerm   RetentionPolicyType = "long_term"  // Long-term retention (e.g., 7 years)
	RetentionArchived   RetentionPolicyType = "archived"   // Archived data (separate policy)
	RetentionRegulated  RetentionPolicyType = "regulated"  // Retention driven by regulations
)

// DataAccessRecord records access to data
type DataAccessRecord struct {
	Timestamp time.Time `json:"timestamp"`
	UserID    string    `json:"user_id"`
	Action    string    `json:"action"`
	Reason    string    `json:"reason,omitempty"`
	IP        string    `json:"ip,omitempty"`
}

// ClassificationRules defines a set of rules for automatically classifying data
type ClassificationRules struct {
	FieldPatterns         map[string]DataClassification       // Field name patterns
	ContentPatterns       map[string]DataClassification       // Content patterns
	CategoryRules         map[DataCategory]DataClassification // Category-based rules
	OverrideRules         []ClassificationOverrideRule        // Rules that can override others
	DefaultClassification DataClassification                  // Default classification
}

// ClassificationOverrideRule defines a rule that can override other classifications
type ClassificationOverrideRule struct {
	Condition      string // Condition expression
	Classification DataClassification
	Reason         string
}

// RetentionPolicy defines a data retention policy
type RetentionPolicy struct {
	Type               RetentionPolicyType
	Duration           time.Duration
	AppliesTo          []DataClassification
	AppliesCategories  []DataCategory
	ExceptionCondition string
	Jurisdiction       string
	AutoDelete         bool
	RequiresApproval   bool
	Description        string
}

// ClassificationMatcher provides functionality to match and classify data
type ClassificationMatcher struct {
	rules ClassificationRules
}

// NewClassificationMatcher creates a new classification matcher
func NewClassificationMatcher(rules ClassificationRules) *ClassificationMatcher {
	return &ClassificationMatcher{
		rules: rules,
	}
}

// ClassifyField classifies a field based on its name and value
func (m *ClassificationMatcher) ClassifyField(fieldName, fieldValue string) DataClassification {
	// First check specific field patterns
	for pattern, classification := range m.rules.FieldPatterns {
		if MatchesPattern(fieldName, pattern) {
			return classification
		}
	}

	// Then check content patterns
	for pattern, classification := range m.rules.ContentPatterns {
		if MatchesPattern(fieldValue, pattern) {
			return classification
		}
	}

	// Use default classification
	return m.rules.DefaultClassification
}

// ClassifyObject classifies an entire object
func (m *ClassificationMatcher) ClassifyObject(obj map[string]interface{}) DataAttributes {
	// Start with default attributes
	attrs := DataAttributes{
		Classification: m.rules.DefaultClassification,
		Categories:     []DataCategory{},
		Tags:           make(map[string]string),
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	// Determine highest classification from fields
	for fieldName, fieldValue := range obj {
		if strValue, ok := fieldValue.(string); ok {
			fieldClass := m.ClassifyField(fieldName, strValue)
			if IsHigherClassification(fieldClass, attrs.Classification) {
				attrs.Classification = fieldClass
			}
		}
	}

	// Apply category-based classification
	for _, category := range attrs.Categories {
		if classification, exists := m.rules.CategoryRules[category]; exists {
			if IsHigherClassification(classification, attrs.Classification) {
				attrs.Classification = classification
			}
		}
	}

	// Set default retention policy based on classification
	attrs.RetentionPolicy = GetDefaultRetentionPolicy(attrs.Classification)
	attrs.RetentionDate = CalculateRetentionDate(attrs.RetentionPolicy)

	return attrs
}

// RetentionManager handles data retention
type RetentionManager struct {
	policies      []RetentionPolicy
	defaultPolicy RetentionPolicy
}

// NewRetentionManager creates a new retention manager
func NewRetentionManager(policies []RetentionPolicy, defaultPolicy RetentionPolicy) *RetentionManager {
	return &RetentionManager{
		policies:      policies,
		defaultPolicy: defaultPolicy,
	}
}

// GetRetentionPolicy gets the appropriate retention policy
func (m *RetentionManager) GetRetentionPolicy(attrs DataAttributes) RetentionPolicy {
	// Match policy based on classification and categories
	for _, policy := range m.policies {
		// Check if policy applies to this classification
		classificationMatches := false
		for _, classification := range policy.AppliesTo {
			if attrs.Classification == classification {
				classificationMatches = true
				break
			}
		}

		if !classificationMatches {
			continue
		}

		// Check if policy applies to any of the categories
		categoryMatches := len(policy.AppliesCategories) == 0
		for _, policyCategory := range policy.AppliesCategories {
			for _, dataCategory := range attrs.Categories {
				if policyCategory == dataCategory {
					categoryMatches = true
					break
				}
			}
			if categoryMatches {
				break
			}
		}

		if categoryMatches {
			return policy
		}
	}

	// Return default policy if no specific policy matches
	return m.defaultPolicy
}

// CalculateRetentionDate calculates the retention date based on policy
func CalculateRetentionDate(policyType RetentionPolicyType) time.Time {
	now := time.Now()

	switch policyType {
	case RetentionIndefinite:
		// Far future date
		return now.AddDate(100, 0, 0)
	case RetentionTransient:
		// 24 hours
		return now.Add(24 * time.Hour)
	case RetentionShortTerm:
		// 30 days
		return now.AddDate(0, 0, 30)
	case RetentionStandard:
		// 1 year
		return now.AddDate(1, 0, 0)
	case RetentionLongTerm:
		// 7 years
		return now.AddDate(7, 0, 0)
	case RetentionArchived:
		// 10 years
		return now.AddDate(10, 0, 0)
	case RetentionRegulated:
		// Default to 7 years for regulated data
		return now.AddDate(7, 0, 0)
	default:
		// Default to 1 year
		return now.AddDate(1, 0, 0)
	}
}

// GetDefaultRetentionPolicy returns the default retention policy for a classification
func GetDefaultRetentionPolicy(classification DataClassification) RetentionPolicyType {
	switch classification {
	case ClassificationPublic:
		return RetentionStandard
	case ClassificationInternal:
		return RetentionStandard
	case ClassificationConfidential:
		return RetentionLongTerm
	case ClassificationSensitive:
		return RetentionRegulated
	case ClassificationRestricted:
		return RetentionRegulated
	default:
		return RetentionStandard
	}
}

// IsHigherClassification checks if one classification is higher than another
func IsHigherClassification(a, b DataClassification) bool {
	classificationOrder := map[DataClassification]int{
		ClassificationPublic:       0,
		ClassificationInternal:     1,
		ClassificationConfidential: 2,
		ClassificationSensitive:    3,
		ClassificationRestricted:   4,
	}

	return classificationOrder[a] > classificationOrder[b]
}

// MatchesPattern checks if a string matches a pattern (simple implementation)
func MatchesPattern(s, pattern string) bool {
	// In a real implementation, this would use regex or more sophisticated matching
	// This is a simplified example
	return s == pattern
}
