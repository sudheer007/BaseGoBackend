package security

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// SecurityEventType represents the type of security event
type SecurityEventType string

const (
	// EventTypeAuth represents authentication-related events
	EventTypeAuth SecurityEventType = "AUTH"

	// EventTypeAccess represents access control events
	EventTypeAccess SecurityEventType = "ACCESS"

	// EventTypeData represents data security events
	EventTypeData SecurityEventType = "DATA"

	// EventTypeSystem represents system security events
	EventTypeSystem SecurityEventType = "SYSTEM"

	// EventTypeAPI represents API security events
	EventTypeAPI SecurityEventType = "API"
)

// SecurityEventSeverity represents the severity of a security event
type SecurityEventSeverity string

const (
	// SeverityCritical is for events requiring immediate attention
	SeverityCritical SecurityEventSeverity = "CRITICAL"

	// SeverityHigh is for significant security events
	SeverityHigh SecurityEventSeverity = "HIGH"

	// SeverityMedium is for moderate security concerns
	SeverityMedium SecurityEventSeverity = "MEDIUM"

	// SeverityLow is for minor security events
	SeverityLow SecurityEventSeverity = "LOW"

	// SeverityInfo is for informational security events
	SeverityInfo SecurityEventSeverity = "INFO"
)

// SecurityEvent represents a security-related event
type SecurityEvent struct {
	// ID is the unique identifier for the event
	ID string

	// Timestamp is when the event occurred
	Timestamp time.Time

	// Type categorizes the event
	Type SecurityEventType

	// Subtype provides more specific event categorization
	Subtype string

	// Severity indicates the event's severity level
	Severity SecurityEventSeverity

	// UserID identifies the user associated with the event
	UserID string

	// TenantID identifies the tenant associated with the event
	TenantID string

	// Source indicates where the event originated
	Source string

	// IPAddress is the IP address associated with the event
	IPAddress string

	// RequestID links the event to a specific request
	RequestID string

	// ResourceID identifies the resource involved in the event
	ResourceID string

	// ResourceType indicates the type of resource involved
	ResourceType string

	// Action describes what was attempted or done
	Action string

	// Status indicates if the action succeeded or failed
	Status string

	// Details contains additional event information
	Details map[string]interface{}

	// RawData contains any raw event data
	RawData []byte

	// RelatedEvents contains IDs of related events
	RelatedEvents []string
}

// NewSecurityEvent creates a new security event
func NewSecurityEvent(ctx context.Context, eventType SecurityEventType, severity SecurityEventSeverity, action, status string) *SecurityEvent {
	requestID := getMonitoringRequestIDFromContext(ctx)
	userID := getMonitoringUserIDFromContext(ctx)
	tenantID := getMonitoringTenantIDFromContext(ctx)
	ipAddress := getMonitoringIPAddressFromContext(ctx)

	return &SecurityEvent{
		ID:        generateMonitoringEventID(),
		Timestamp: time.Now(),
		Type:      eventType,
		Severity:  severity,
		UserID:    userID,
		TenantID:  tenantID,
		Source:    "API",
		IPAddress: ipAddress,
		RequestID: requestID,
		Action:    action,
		Status:    status,
		Details:   make(map[string]interface{}),
	}
}

// String returns a string representation of the event
func (e *SecurityEvent) String() string {
	return fmt.Sprintf("[%s] %s - %s - User: %s, Tenant: %s, Action: %s, Status: %s",
		e.Severity, e.Type, e.Timestamp.Format(time.RFC3339),
		e.UserID, e.TenantID, e.Action, e.Status)
}

// SecurityMonitor is responsible for monitoring and alerting on security events
type SecurityMonitor struct {
	// publishers are the registered event publishers
	publishers []SecurityEventPublisher

	// alerters are the registered alert handlers
	alerters []SecurityAlerter

	// thresholds define alert thresholds by event type and severity
	thresholds map[string]int

	// eventCounts track event counts for threshold alerting
	eventCounts *EventCounter

	// eventCountsLock protects the eventCounts
	eventCountsLock sync.RWMutex
}

// SecurityEventPublisher defines an interface for components that publish security events
type SecurityEventPublisher interface {
	// Subscribe registers a handler to receive events
	Subscribe(handler func(event *SecurityEvent))
}

// SecurityAlerter defines an interface for components that handle security alerts
type SecurityAlerter interface {
	// Name returns the name of the alerter
	Name() string

	// Alert sends an alert based on the security event
	Alert(ctx context.Context, event *SecurityEvent) error

	// ShouldAlert determines if this alerter should handle the event
	ShouldAlert(event *SecurityEvent) bool
}

// EventCounter tracks security event counts for threshold-based alerting
type EventCounter struct {
	// counts maps event type and severity to counts
	counts map[string]int

	// lastReset is when counts were last reset
	lastReset time.Time

	// window is the time window for counting events
	window time.Duration
}

// NewEventCounter creates a new event counter with the specified window
func NewEventCounter(window time.Duration) *EventCounter {
	return &EventCounter{
		counts:    make(map[string]int),
		lastReset: time.Now(),
		window:    window,
	}
}

// Increment increases the count for a specific event type and severity
func (c *EventCounter) Increment(eventType SecurityEventType, severity SecurityEventSeverity) {
	key := fmt.Sprintf("%s:%s", eventType, severity)
	c.counts[key]++
}

// Count returns the current count for a specific event type and severity
func (c *EventCounter) Count(eventType SecurityEventType, severity SecurityEventSeverity) int {
	key := fmt.Sprintf("%s:%s", eventType, severity)
	return c.counts[key]
}

// ResetIfNeeded resets counts if the window has passed
func (c *EventCounter) ResetIfNeeded() {
	if time.Since(c.lastReset) > c.window {
		c.counts = make(map[string]int)
		c.lastReset = time.Now()
	}
}

// NewSecurityMonitor creates a new security monitoring system
func NewSecurityMonitor() *SecurityMonitor {
	return &SecurityMonitor{
		publishers:  make([]SecurityEventPublisher, 0),
		alerters:    make([]SecurityAlerter, 0),
		thresholds:  make(map[string]int),
		eventCounts: NewEventCounter(10 * time.Minute),
	}
}

// RegisterPublisher adds a security event publisher
func (m *SecurityMonitor) RegisterPublisher(publisher SecurityEventPublisher) {
	m.publishers = append(m.publishers, publisher)

	// Subscribe to publisher events
	publisher.Subscribe(func(event *SecurityEvent) {
		m.handleEvent(context.Background(), event)
	})
}

// RegisterAlerter adds a security alerter
func (m *SecurityMonitor) RegisterAlerter(alerter SecurityAlerter) {
	m.alerters = append(m.alerters, alerter)
}

// SetThreshold sets an alert threshold for a specific event type and severity
func (m *SecurityMonitor) SetThreshold(eventType SecurityEventType, severity SecurityEventSeverity, count int) {
	key := fmt.Sprintf("%s:%s", eventType, severity)
	m.thresholds[key] = count
}

// LogEvent logs a security event and triggers alerts if needed
func (m *SecurityMonitor) LogEvent(ctx context.Context, event *SecurityEvent) {
	// Process the event
	m.handleEvent(ctx, event)
}

// handleEvent processes a security event
func (m *SecurityMonitor) handleEvent(ctx context.Context, event *SecurityEvent) {
	// Update event counts for threshold alerting
	m.eventCountsLock.Lock()
	m.eventCounts.ResetIfNeeded()
	m.eventCounts.Increment(event.Type, event.Severity)
	count := m.eventCounts.Count(event.Type, event.Severity)
	m.eventCountsLock.Unlock()

	// Log the event
	logMonitoringEvent(event)

	// Check if we should alert based on individual event
	shouldSendIndividualAlert := event.Severity == SeverityCritical ||
		(event.Severity == SeverityHigh && (event.Type == EventTypeAuth || event.Type == EventTypeSystem))

	// Check if we should alert based on threshold
	key := fmt.Sprintf("%s:%s", event.Type, event.Severity)
	threshold, exists := m.thresholds[key]
	shouldSendThresholdAlert := exists && count >= threshold

	// Send alerts if needed
	if shouldSendIndividualAlert || shouldSendThresholdAlert {
		m.sendAlerts(ctx, event)
	}
}

// sendAlerts sends the event to all relevant alerters
func (m *SecurityMonitor) sendAlerts(ctx context.Context, event *SecurityEvent) {
	for _, alerter := range m.alerters {
		if alerter.ShouldAlert(event) {
			go func(a SecurityAlerter, e *SecurityEvent) {
				if err := a.Alert(ctx, e); err != nil {
					fmt.Printf("Failed to send alert to %s: %v\n", a.Name(), err)
				}
			}(alerter, event)
		}
	}
}

// Interface implementations

// HTTPRequestEventPublisher publishes security events from HTTP requests
type HTTPRequestEventPublisher struct {
	handlers []func(event *SecurityEvent)
}

// NewHTTPRequestEventPublisher creates a new HTTP request event publisher
func NewHTTPRequestEventPublisher() *HTTPRequestEventPublisher {
	return &HTTPRequestEventPublisher{
		handlers: make([]func(event *SecurityEvent), 0),
	}
}

// Subscribe registers a handler to receive events
func (p *HTTPRequestEventPublisher) Subscribe(handler func(event *SecurityEvent)) {
	p.handlers = append(p.handlers, handler)
}

// PublishFromRequest creates and publishes a security event from an HTTP request
func (p *HTTPRequestEventPublisher) PublishFromRequest(r *http.Request, eventType SecurityEventType, severity SecurityEventSeverity, action, status string) {
	ctx := r.Context()
	event := NewSecurityEvent(ctx, eventType, severity, action, status)
	event.Source = "HTTP"
	event.IPAddress = getMonitoringClientIP(r)

	// Add request details
	event.Details["method"] = r.Method
	event.Details["path"] = r.URL.Path
	event.Details["user_agent"] = r.UserAgent()

	p.publish(event)
}

// publish sends the event to all registered handlers
func (p *HTTPRequestEventPublisher) publish(event *SecurityEvent) {
	for _, handler := range p.handlers {
		handler(event)
	}
}

// ConsoleAlerter outputs security alerts to the console
type ConsoleAlerter struct{}

// Name returns the name of the alerter
func (a *ConsoleAlerter) Name() string {
	return "Console"
}

// Alert sends an alert based on the security event
func (a *ConsoleAlerter) Alert(ctx context.Context, event *SecurityEvent) error {
	fmt.Printf("🚨 SECURITY ALERT 🚨 - %s\n", event.String())
	return nil
}

// ShouldAlert determines if this alerter should handle the event
func (a *ConsoleAlerter) ShouldAlert(event *SecurityEvent) bool {
	// Console alerter handles all events
	return true
}

// WebhookAlerter sends security alerts to a webhook
type WebhookAlerter struct {
	webhookURL string
	client     *http.Client
	// Alerting rules determine which events get sent to which webhooks
	severityThreshold SecurityEventSeverity
	eventTypes        []SecurityEventType
}

// NewWebhookAlerter creates a new webhook alerter
func NewWebhookAlerter(webhookURL string, severityThreshold SecurityEventSeverity, eventTypes []SecurityEventType) *WebhookAlerter {
	return &WebhookAlerter{
		webhookURL:        webhookURL,
		client:            &http.Client{Timeout: 10 * time.Second},
		severityThreshold: severityThreshold,
		eventTypes:        eventTypes,
	}
}

// Name returns the name of the alerter
func (a *WebhookAlerter) Name() string {
	return "Webhook"
}

// Alert sends an alert based on the security event
func (a *WebhookAlerter) Alert(ctx context.Context, event *SecurityEvent) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", a.webhookURL, strings.NewReader(string(payload)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}

// ShouldAlert determines if this alerter should handle the event
func (a *WebhookAlerter) ShouldAlert(event *SecurityEvent) bool {
	// Check severity threshold
	if !isSeverityAtLeast(event.Severity, a.severityThreshold) {
		return false
	}

	// Check if event type is in our list
	if len(a.eventTypes) > 0 {
		for _, t := range a.eventTypes {
			if event.Type == t {
				return true
			}
		}
		return false
	}

	// If no event types specified, handle all events that meet the severity threshold
	return true
}

// Helper functions

// logMonitoringEvent logs a security event
func logMonitoringEvent(event *SecurityEvent) {
	// In a real system, this would write to a secure log store
	fmt.Printf("[%s] %s - %s - User: %s, Action: %s, Status: %s\n",
		event.Severity, event.Type, event.Timestamp.Format(time.RFC3339),
		event.UserID, event.Action, event.Status)
}

// isSeverityAtLeast checks if a severity is at least a threshold
func isSeverityAtLeast(severity, threshold SecurityEventSeverity) bool {
	severityLevels := map[SecurityEventSeverity]int{
		SeverityCritical: 5,
		SeverityHigh:     4,
		SeverityMedium:   3,
		SeverityLow:      2,
		SeverityInfo:     1,
	}

	return severityLevels[severity] >= severityLevels[threshold]
}

// generateMonitoringEventID creates a unique event ID
func generateMonitoringEventID() string {
	return fmt.Sprintf("evt-%d", time.Now().UnixNano())
}

// getMonitoringRequestIDFromContext extracts the request ID from the context
func getMonitoringRequestIDFromContext(ctx context.Context) string {
	// Implement based on your request tracking system
	// This is a placeholder
	return fmt.Sprintf("req-%d", time.Now().UnixNano())
}

// getMonitoringUserIDFromContext extracts the user ID from the context
func getMonitoringUserIDFromContext(ctx context.Context) string {
	// Implement based on your authentication system
	// This is a placeholder
	return "unknown"
}

// getMonitoringTenantIDFromContext extracts the tenant ID from the context
func getMonitoringTenantIDFromContext(ctx context.Context) string {
	// Implement based on your multi-tenant system
	// This is a placeholder
	return "unknown"
}

// getMonitoringIPAddressFromContext extracts the IP address from the context
func getMonitoringIPAddressFromContext(ctx context.Context) string {
	// Implement based on your context structure
	// This is a placeholder
	return "0.0.0.0"
}

// getMonitoringClientIP extracts the client IP from the request
func getMonitoringClientIP(r *http.Request) string {
	// Try X-Forwarded-For header first
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		// X-Forwarded-For can contain multiple IPs; use the first one
		ips := strings.Split(forwarded, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Try X-Real-IP header
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}

	// Fall back to RemoteAddr
	return r.RemoteAddr
}

// SecurityMonitorMiddleware is middleware for monitoring security events from HTTP requests
type SecurityMonitorMiddleware struct {
	monitor   *SecurityMonitor
	publisher *HTTPRequestEventPublisher
}

// NewSecurityMonitorMiddleware creates a new security monitoring middleware
func NewSecurityMonitorMiddleware(monitor *SecurityMonitor) *SecurityMonitorMiddleware {
	publisher := NewHTTPRequestEventPublisher()
	monitor.RegisterPublisher(publisher)

	return &SecurityMonitorMiddleware{
		monitor:   monitor,
		publisher: publisher,
	}
}

// Middleware returns an HTTP middleware function
func (m *SecurityMonitorMiddleware) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Create a response recorder to capture the status code
			recorder := NewSecurityResponseRecorder(w)

			// Process the request
			next.ServeHTTP(recorder, r)

			// Log security event for the request
			statusText := "success"
			var severity SecurityEventSeverity

			// Determine severity based on status code
			statusCode := recorder.Status()
			switch {
			case statusCode >= 500:
				severity = SeverityHigh
				statusText = "error"
			case statusCode >= 400:
				if statusCode == 401 || statusCode == 403 {
					severity = SeverityMedium
					statusText = "denied"
				} else {
					severity = SeverityLow
					statusText = "failed"
				}
			case statusCode >= 200 && statusCode < 300:
				severity = SeverityInfo
			default:
				severity = SeverityInfo
			}

			// Determine event type based on path and method
			eventType := determineSecurityEventType(r)

			// Log the request as a security event
			action := fmt.Sprintf("%s %s", r.Method, r.URL.Path)
			m.publisher.PublishFromRequest(r, eventType, severity, action, statusText)
		})
	}
}

// determineSecurityEventType determines the security event type based on the request
func determineSecurityEventType(r *http.Request) SecurityEventType {
	path := r.URL.Path
	method := r.Method

	// Authentication-related endpoints
	if strings.Contains(path, "/auth") || strings.Contains(path, "/login") || strings.Contains(path, "/logout") {
		return EventTypeAuth
	}

	// User or permission management
	if strings.Contains(path, "/users") || strings.Contains(path, "/roles") || strings.Contains(path, "/permissions") {
		return EventTypeAccess
	}

	// Data-related operations
	if method == "POST" || method == "PUT" || method == "PATCH" || method == "DELETE" {
		return EventTypeData
	}

	// System configuration
	if strings.Contains(path, "/admin") || strings.Contains(path, "/config") || strings.Contains(path, "/system") {
		return EventTypeSystem
	}

	// Default to API
	return EventTypeAPI
}

// SecurityResponseRecorder is a custom ResponseWriter that records the response
type SecurityResponseRecorder struct {
	http.ResponseWriter
	statusCode int
	size       int64
	body       []byte
}

// NewSecurityResponseRecorder creates a new ResponseRecorder
func NewSecurityResponseRecorder(w http.ResponseWriter) *SecurityResponseRecorder {
	return &SecurityResponseRecorder{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
	}
}

// WriteHeader implements http.ResponseWriter
func (r *SecurityResponseRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

// Write implements http.ResponseWriter
func (r *SecurityResponseRecorder) Write(b []byte) (int, error) {
	r.body = append(r.body, b...)
	size, err := r.ResponseWriter.Write(b)
	r.size += int64(size)
	return size, err
}

// Status returns the status code
func (r *SecurityResponseRecorder) Status() int {
	return r.statusCode
}

// Size returns the size of the response
func (r *SecurityResponseRecorder) Size() int64 {
	return r.size
}

// Body returns the body of the response
func (r *SecurityResponseRecorder) Body() []byte {
	return r.body
}
