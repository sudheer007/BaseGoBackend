package security

import (
	"context"
	"fmt"
	"net/http"

	"gobackend/internal/security/securitymonitoring"
)

// Expose SecurityMonitorMiddleware from securitymonitoring package
// This allows existing code to use security.SecurityMonitorMiddleware

// MonitorMiddleware provides security monitoring middleware
type MonitorMiddleware struct {
	monitor *securitymonitoring.SecurityMonitor
	impl    *securitymonitoring.SecurityMonitorMiddleware
}

// NewMonitorMiddleware creates a new security monitoring middleware
func NewMonitorMiddleware() *MonitorMiddleware {
	monitor := securitymonitoring.NewSecurityMonitor()
	return &MonitorMiddleware{
		monitor: monitor,
		impl:    securitymonitoring.NewSecurityMonitorMiddleware(monitor),
	}
}

// Middleware returns an HTTP middleware handler
func (m *MonitorMiddleware) Middleware() func(http.Handler) http.Handler {
	return m.impl.Middleware()
}

// LogSecurityEvent logs a security event to the monitor
func (m *MonitorMiddleware) LogSecurityEvent(ctx context.Context, eventType securitymonitoring.SecurityEventType,
	severity securitymonitoring.SecurityEventSeverity, action, status string) {

	event := securitymonitoring.NewSecurityEvent(ctx, eventType, severity, action, status)
	// Log the event via the monitor
	m.monitor.LogEvent(ctx, event)

	// Also print it to console (for backward compatibility)
	fmt.Printf("[%s] %s - User: %s, Action: %s, Status: %s\n",
		event.Severity, event.Type, event.UserID, event.Action, event.Status)
}
