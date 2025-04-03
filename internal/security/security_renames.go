package security

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"gobackend/internal/security/securitymonitoring"
)

// ExfilResponseRecorder is a custom ResponseWriter used in exfiltration prevention
type ExfilResponseRecorder struct {
	http.ResponseWriter
	statusCode int
	size       int64
	body       []byte
}

// NewExfilResponseRecorder creates a new ExfilResponseRecorder
func NewExfilResponseRecorder(w http.ResponseWriter) *ExfilResponseRecorder {
	return &ExfilResponseRecorder{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
	}
}

// WriteHeader implements http.ResponseWriter
func (r *ExfilResponseRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

// Write implements http.ResponseWriter
func (r *ExfilResponseRecorder) Write(b []byte) (int, error) {
	r.body = append(r.body, b...)
	size, err := r.ResponseWriter.Write(b)
	r.size += int64(size)
	return size, err
}

// Status returns the status code
func (r *ExfilResponseRecorder) Status() int {
	return r.statusCode
}

// Size returns the size of the response
func (r *ExfilResponseRecorder) Size() int64 {
	return r.size
}

// Body returns the body of the response
func (r *ExfilResponseRecorder) Body() []byte {
	return r.body
}

// MonitorResponseRecorder is a custom ResponseWriter used in security monitoring
type MonitorResponseRecorder struct {
	http.ResponseWriter
	statusCode int
	size       int64
	body       []byte
}

// NewMonitorResponseRecorder creates a new MonitorResponseRecorder
func NewMonitorResponseRecorder(w http.ResponseWriter) *MonitorResponseRecorder {
	return &MonitorResponseRecorder{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
	}
}

// WriteHeader implements http.ResponseWriter
func (r *MonitorResponseRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

// Write implements http.ResponseWriter
func (r *MonitorResponseRecorder) Write(b []byte) (int, error) {
	r.body = append(r.body, b...)
	size, err := r.ResponseWriter.Write(b)
	r.size += int64(size)
	return size, err
}

// Status returns the status code
func (r *MonitorResponseRecorder) Status() int {
	return r.statusCode
}

// Size returns the size of the response
func (r *MonitorResponseRecorder) Size() int64 {
	return r.size
}

// Body returns the body of the response
func (r *MonitorResponseRecorder) Body() []byte {
	return r.body
}

// Common utility functions for context extraction

// GetUserIDFromExfilContext extracts the user ID from context for exfiltration prevention
func GetUserIDFromExfilContext(ctx context.Context) string {
	// Implement based on your authentication system
	// This is a placeholder
	return "unknown"
}

// GetTenantIDFromExfilContext extracts the tenant ID from context for exfiltration prevention
func GetTenantIDFromExfilContext(ctx context.Context) string {
	// Implement based on your multi-tenant system
	// This is a placeholder
	return "unknown"
}

// GetRequestIDFromExfilContext extracts the request ID from context for exfiltration prevention
func GetRequestIDFromExfilContext(ctx context.Context) string {
	// Implement based on your request tracking system
	// This is a placeholder
	return fmt.Sprintf("req-%d", time.Now().UnixNano())
}

// GetUserIDFromMonitorContext extracts the user ID from context for security monitoring
func GetUserIDFromMonitorContext(ctx context.Context) string {
	// Implement based on your authentication system
	// This is a placeholder
	return "unknown"
}

// GetTenantIDFromMonitorContext extracts the tenant ID from context for security monitoring
func GetTenantIDFromMonitorContext(ctx context.Context) string {
	// Implement based on your multi-tenant system
	// This is a placeholder
	return "unknown"
}

// GetRequestIDFromMonitorContext extracts the request ID from context for security monitoring
func GetRequestIDFromMonitorContext(ctx context.Context) string {
	// Implement based on your request tracking system
	// This is a placeholder
	return fmt.Sprintf("req-%d", time.Now().UnixNano())
}

// GetIPAddressFromMonitorContext extracts the IP address from context for security monitoring
func GetIPAddressFromMonitorContext(ctx context.Context) string {
	// Implement based on your context structure
	// This is a placeholder
	return "0.0.0.0"
}

// GetExfilClientIP extracts the client IP from the request for exfiltration prevention
func GetExfilClientIP(r *http.Request) string {
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

// GetMonitorClientIP extracts the client IP from the request for security monitoring
func GetMonitorClientIP(r *http.Request) string {
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

// MonitorSeverityAtLeast checks if a security monitor severity is at least a threshold
func MonitorSeverityAtLeast(severity, threshold securitymonitoring.SecurityEventSeverity) bool {
	severityLevels := map[securitymonitoring.SecurityEventSeverity]int{
		securitymonitoring.SeverityCritical: 5,
		securitymonitoring.SeverityHigh:     4,
		securitymonitoring.SeverityMedium:   3,
		securitymonitoring.SeverityLow:      2,
		securitymonitoring.SeverityInfo:     1,
	}

	return severityLevels[severity] >= severityLevels[threshold]
}
