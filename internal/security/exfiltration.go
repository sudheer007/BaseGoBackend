package security

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// ExfiltrationType represents the type of data exfiltration attempt
type ExfiltrationType string

const (
	// ExfiltrationTypeLargeDataResponse represents an unusually large response
	ExfiltrationTypeLargeDataResponse ExfiltrationType = "LARGE_DATA_RESPONSE"

	// ExfiltrationTypeSensitiveDataDetected represents detected sensitive data in response
	ExfiltrationTypeSensitiveDataDetected ExfiltrationType = "SENSITIVE_DATA_DETECTED"

	// ExfiltrationTypeAnomalousAccess represents anomalous data access pattern
	ExfiltrationTypeAnomalousAccess ExfiltrationType = "ANOMALOUS_ACCESS"

	// ExfiltrationTypeHighFrequencyAccess represents high frequency data access
	ExfiltrationTypeHighFrequencyAccess ExfiltrationType = "HIGH_FREQUENCY_ACCESS"

	// ExfiltrationTypeUnauthorizedExport represents unauthorized data export
	ExfiltrationTypeUnauthorizedExport ExfiltrationType = "UNAUTHORIZED_EXPORT"
)

// Common errors
var (
	ErrLargeDataTransfer      = errors.New("data transfer exceeds allowed threshold")
	ErrSensitiveDataExposure  = errors.New("sensitive data detected in response")
	ErrAnomalousDataAccess    = errors.New("anomalous data access pattern detected")
	ErrRateLimitExceeded      = errors.New("rate limit exceeded for data access")
	ErrUnauthorizedDataExport = errors.New("unauthorized data export attempt")
)

// ExfiltrationConfig holds configuration for exfiltration prevention
type ExfiltrationConfig struct {
	// MaxResponseSize is the maximum allowed size for responses in bytes
	MaxResponseSize int64

	// MaxRequestsPerMinute is the maximum number of requests allowed per minute
	MaxRequestsPerMinute int

	// SensitiveDataPatterns contains regex patterns for sensitive data detection
	SensitiveDataPatterns []*regexp.Regexp

	// EnableAnomalyDetection enables behavioral anomaly detection
	EnableAnomalyDetection bool

	// ExportApprovers contains user IDs authorized to approve exports
	ExportApprovers []string

	// AlertThreshold is the number of violations before triggering an alert
	AlertThreshold int
}

// DefaultExfiltrationConfig returns a default configuration
func DefaultExfiltrationConfig() *ExfiltrationConfig {
	return &ExfiltrationConfig{
		MaxResponseSize:        5 * 1024 * 1024, // 5MB
		MaxRequestsPerMinute:   300,
		SensitiveDataPatterns:  defaultSensitiveDataPatterns(),
		EnableAnomalyDetection: true,
		AlertThreshold:         3,
	}
}

// defaultSensitiveDataPatterns returns a set of default regex patterns for sensitive data
func defaultSensitiveDataPatterns() []*regexp.Regexp {
	patterns := []string{
		// Credit card numbers
		`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b`,
		// Social Security numbers
		`\b(?!000|666|9\d{2})([0-8]\d{2}|7([0-6]\d))([-]?)((?!00)\d{2}\3(?!0000)\d{4})\b`,
		// API keys and tokens (generic pattern)
		`(?i)(api_key|api[-_]?token|access[-_]?token|secret[-_]?key|bearer)[-_]?[:=][-_]?["']?[a-zA-Z0-9_\-\.]{20,}["']?`,
		// Email addresses
		`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`,
	}

	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err == nil {
			compiled = append(compiled, re)
		}
	}

	return compiled
}

// ExfiltrationEvent represents a detected exfiltration attempt
type ExfiltrationEvent struct {
	Timestamp   time.Time
	UserID      string
	TenantID    string
	RequestPath string
	RequestID   string
	RemoteIP    string
	Type        ExfiltrationType
	Details     string
	Severity    string
}

// ExfiltrationPreventionMiddleware is middleware that helps prevent data exfiltration
type ExfiltrationPreventionMiddleware struct {
	config        *ExfiltrationConfig
	alerter       ExfiltrationAlerter
	accessTracker *AccessTracker
}

// ExfiltrationAlerter defines the interface for alerting on exfiltration attempts
type ExfiltrationAlerter interface {
	// Alert sends an alert about a potential exfiltration attempt
	Alert(ctx context.Context, event ExfiltrationEvent) error
}

// NewExfiltrationPreventionMiddleware creates a new middleware instance
func NewExfiltrationPreventionMiddleware(config *ExfiltrationConfig, alerter ExfiltrationAlerter) *ExfiltrationPreventionMiddleware {
	if config == nil {
		config = DefaultExfiltrationConfig()
	}

	return &ExfiltrationPreventionMiddleware{
		config:        config,
		alerter:       alerter,
		accessTracker: NewAccessTracker(),
	}
}

// Middleware returns an HTTP middleware function
func (m *ExfiltrationPreventionMiddleware) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			userID := GetUserIDFromExfilContext(ctx)
			tenantID := GetTenantIDFromExfilContext(ctx)

			// Check rate limiting for data access
			if err := m.checkRateLimit(userID, r.URL.Path); err != nil {
				m.handleViolation(ctx, ExfiltrationTypeHighFrequencyAccess, userID, tenantID, r, err.Error())
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			// Check for export authorization
			if isExportRequest(r) && !m.isAuthorizedForExport(userID) {
				m.handleViolation(ctx, ExfiltrationTypeUnauthorizedExport, userID, tenantID, r, "Unauthorized export attempt")
				http.Error(w, "Unauthorized", http.StatusForbidden)
				return
			}

			// Create a recording response writer to inspect the response
			recorder := NewExfilResponseRecorder(w)

			// Process the request
			next.ServeHTTP(recorder, r)

			// Post-processing checks

			// Check response size
			if recorder.Size() > m.config.MaxResponseSize {
				details := fmt.Sprintf("Response size %d exceeds maximum allowed %d", recorder.Size(), m.config.MaxResponseSize)
				m.handleViolation(ctx, ExfiltrationTypeLargeDataResponse, userID, tenantID, r, details)
				// Response already sent, can't modify it, but we can log and alert
			}

			// Check for sensitive data in response
			if m.containsSensitiveData(recorder.Body()) {
				m.handleViolation(ctx, ExfiltrationTypeSensitiveDataDetected, userID, tenantID, r, "Sensitive data detected in response")
				// Response already sent, can't modify it, but we can log and alert
			}

			// Check for anomalous access patterns
			if m.config.EnableAnomalyDetection && m.isAnomalousAccess(userID, tenantID, r.URL.Path) {
				m.handleViolation(ctx, ExfiltrationTypeAnomalousAccess, userID, tenantID, r, "Anomalous data access pattern")
				// Response already sent, can't modify it, but we can log and alert
			}

			// Track this access for future anomaly detection
			m.accessTracker.TrackAccess(userID, tenantID, r.URL.Path)
		})
	}
}

// handleViolation processes a detected violation
func (m *ExfiltrationPreventionMiddleware) handleViolation(ctx context.Context, violationType ExfiltrationType, userID, tenantID string, r *http.Request, details string) {
	event := ExfiltrationEvent{
		Timestamp:   time.Now(),
		UserID:      userID,
		TenantID:    tenantID,
		RequestPath: r.URL.Path,
		RequestID:   GetRequestIDFromExfilContext(ctx),
		RemoteIP:    GetExfilClientIP(r),
		Type:        violationType,
		Details:     details,
		Severity:    calculateSeverity(violationType),
	}

	// Send alert
	if m.alerter != nil {
		go m.alerter.Alert(ctx, event)
	}

	// Log the event
	logExfiltrationEvent(event)
}

// checkRateLimit checks if the request exceeds rate limits
func (m *ExfiltrationPreventionMiddleware) checkRateLimit(userID, path string) error {
	count := m.accessTracker.GetRecentAccessCount(userID, path, time.Minute)
	if count > m.config.MaxRequestsPerMinute {
		return ErrRateLimitExceeded
	}
	return nil
}

// containsSensitiveData checks if the response contains sensitive data
func (m *ExfiltrationPreventionMiddleware) containsSensitiveData(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	content := string(data)
	for _, pattern := range m.config.SensitiveDataPatterns {
		if pattern.MatchString(content) {
			return true
		}
	}

	return false
}

// isAuthorizedForExport checks if a user is authorized for data export
func (m *ExfiltrationPreventionMiddleware) isAuthorizedForExport(userID string) bool {
	for _, approver := range m.config.ExportApprovers {
		if approver == userID {
			return true
		}
	}
	return false
}

// isAnomalousAccess checks if current access pattern is anomalous
func (m *ExfiltrationPreventionMiddleware) isAnomalousAccess(userID, tenantID, path string) bool {
	// Simplified implementation - in a real system this would use more sophisticated
	// anomaly detection algorithms based on historical access patterns

	// Check if user is accessing unusual paths
	if !m.accessTracker.IsCommonPath(userID, path) {
		return true
	}

	// Check if user is accessing unusual tenants
	if !m.accessTracker.IsCommonTenant(userID, tenantID) {
		return true
	}

	// Check if access volume is unusual
	if m.accessTracker.IsUnusualVolume(userID) {
		return true
	}

	return false
}

// AccessTracker tracks user access patterns for anomaly detection
type AccessTracker struct {
	// Real implementation would use a more efficient data structure
	// and possibly store data in Redis or another distributed cache
	accessLogs map[string][]AccessLog
}

// AccessLog represents a single access log entry
type AccessLog struct {
	UserID    string
	TenantID  string
	Path      string
	Timestamp time.Time
}

// NewAccessTracker creates a new AccessTracker
func NewAccessTracker() *AccessTracker {
	return &AccessTracker{
		accessLogs: make(map[string][]AccessLog),
	}
}

// TrackAccess records an access
func (t *AccessTracker) TrackAccess(userID, tenantID, path string) {
	log := AccessLog{
		UserID:    userID,
		TenantID:  tenantID,
		Path:      path,
		Timestamp: time.Now(),
	}

	key := userID
	if logs, exists := t.accessLogs[key]; exists {
		// Keep only recent logs (last 24 hours)
		cutoff := time.Now().Add(-24 * time.Hour)
		recentLogs := make([]AccessLog, 0, len(logs))

		for _, l := range logs {
			if l.Timestamp.After(cutoff) {
				recentLogs = append(recentLogs, l)
			}
		}

		t.accessLogs[key] = append(recentLogs, log)
	} else {
		t.accessLogs[key] = []AccessLog{log}
	}
}

// GetRecentAccessCount returns the number of accesses in the specified time window
func (t *AccessTracker) GetRecentAccessCount(userID, path string, window time.Duration) int {
	logs, exists := t.accessLogs[userID]
	if !exists {
		return 0
	}

	cutoff := time.Now().Add(-window)
	count := 0

	for _, log := range logs {
		if log.Timestamp.After(cutoff) && (path == "" || log.Path == path) {
			count++
		}
	}

	return count
}

// IsCommonPath checks if a path is commonly accessed by a user
func (t *AccessTracker) IsCommonPath(userID, path string) bool {
	logs, exists := t.accessLogs[userID]
	if !exists {
		return false
	}

	// Count accesses to this path
	pathCount := 0
	for _, log := range logs {
		if log.Path == path {
			pathCount++
		}
	}

	// If path has been accessed at least 3 times or makes up > 5% of accesses, consider it common
	return pathCount >= 3 || (float64(pathCount)/float64(len(logs)) > 0.05)
}

// IsCommonTenant checks if a tenant is commonly accessed by a user
func (t *AccessTracker) IsCommonTenant(userID, tenantID string) bool {
	logs, exists := t.accessLogs[userID]
	if !exists {
		return false
	}

	// Count accesses to this tenant
	tenantCount := 0
	for _, log := range logs {
		if log.TenantID == tenantID {
			tenantCount++
		}
	}

	// If tenant has been accessed at least 3 times or makes up > 10% of accesses, consider it common
	return tenantCount >= 3 || (float64(tenantCount)/float64(len(logs)) > 0.1)
}

// IsUnusualVolume checks if the current access volume is unusual for this user
func (t *AccessTracker) IsUnusualVolume(userID string) bool {
	// Get access count in the last hour
	hourlyCount := t.GetRecentAccessCount(userID, "", time.Hour)

	// Get average hourly count over last 24 hours
	logs, exists := t.accessLogs[userID]
	if !exists {
		return false
	}

	// Calculate hourly average over 24 hours
	cutoff := time.Now().Add(-24 * time.Hour)
	totalLogs := 0
	for _, log := range logs {
		if log.Timestamp.After(cutoff) {
			totalLogs++
		}
	}

	hourlyAverage := float64(totalLogs) / 24.0

	// If current hourly count is more than 3x the average, consider it unusual
	return float64(hourlyCount) > hourlyAverage*3.0
}

// Helper functions

// isExportRequest checks if the request is for data export
func isExportRequest(r *http.Request) bool {
	// Check path
	if strings.Contains(r.URL.Path, "/export") || strings.Contains(r.URL.Path, "/download") {
		return true
	}

	// Check query params
	if r.URL.Query().Get("export") != "" || r.URL.Query().Get("download") != "" || r.URL.Query().Get("format") == "csv" {
		return true
	}

	// Check Accept header for export formats
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "text/csv") ||
		strings.Contains(accept, "application/vnd.ms-excel") ||
		strings.Contains(accept, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet") {
		return true
	}

	return false
}

// calculateSeverity determines the severity level based on violation type
func calculateSeverity(violationType ExfiltrationType) string {
	switch violationType {
	case ExfiltrationTypeSensitiveDataDetected, ExfiltrationTypeUnauthorizedExport:
		return "high"
	case ExfiltrationTypeAnomalousAccess, ExfiltrationTypeLargeDataResponse:
		return "medium"
	case ExfiltrationTypeHighFrequencyAccess:
		return "low"
	default:
		return "info"
	}
}

// logExfiltrationEvent logs an exfiltration event
func logExfiltrationEvent(event ExfiltrationEvent) {
	// Implement based on your logging system
	// This is a placeholder
	fmt.Printf("[%s] EXFILTRATION ALERT: %s - User: %s, Tenant: %s, Path: %s, Details: %s\n",
		event.Severity,
		event.Type,
		event.UserID,
		event.TenantID,
		event.RequestPath,
		event.Details)
}
