package security

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// LogLevel defines the severity of a log entry
type LogLevel string

const (
	// LogLevelDebug is for detailed debug information
	LogLevelDebug LogLevel = "DEBUG"

	// LogLevelInfo is for general information
	LogLevelInfo LogLevel = "INFO"

	// LogLevelWarning is for warning events
	LogLevelWarning LogLevel = "WARNING"

	// LogLevelError is for error events
	LogLevelError LogLevel = "ERROR"

	// LogLevelCritical is for critical security events
	LogLevelCritical LogLevel = "CRITICAL"
)

// LogCategory defines the category of a log entry
type LogCategory string

const (
	// LogCategoryAuth is for authentication events
	LogCategoryAuth LogCategory = "AUTH"

	// LogCategoryAccess is for access control events
	LogCategoryAccess LogCategory = "ACCESS"

	// LogCategoryData is for data-related events
	LogCategoryData LogCategory = "DATA"

	// LogCategoryAudit is for audit events
	LogCategoryAudit LogCategory = "AUDIT"

	// LogCategorySecurity is for general security events
	LogCategorySecurity LogCategory = "SECURITY"

	// LogCategorySystem is for system events
	LogCategorySystem LogCategory = "SYSTEM"
)

// SecurityLogEntry represents a security log entry
type SecurityLogEntry struct {
	// Standard fields
	ID        string      `json:"id"`
	Timestamp time.Time   `json:"timestamp"`
	Level     LogLevel    `json:"level"`
	Category  LogCategory `json:"category"`
	Message   string      `json:"message"`

	// Context information
	SessionID  string `json:"session_id,omitempty"`
	UserID     string `json:"user_id,omitempty"`
	TenantID   string `json:"tenant_id,omitempty"`
	IPAddress  string `json:"ip_address,omitempty"`
	UserAgent  string `json:"user_agent,omitempty"`
	ResourceID string `json:"resource_id,omitempty"`
	RequestID  string `json:"request_id,omitempty"`

	// Security information
	Action      string                 `json:"action,omitempty"`
	Result      string                 `json:"result,omitempty"`
	Reason      string                 `json:"reason,omitempty"`
	Permissions []string               `json:"permissions,omitempty"`
	Roles       []string               `json:"roles,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty"`

	// Chain of custody
	PreviousEntryHash string `json:"previous_entry_hash,omitempty"`
	EntryHash         string `json:"entry_hash"`

	// Sequence info for tamper detection
	SequenceNumber int64 `json:"sequence_number"`
}

// SecurityLogger is a secure logger for security-relevant events
type SecurityLogger struct {
	// Output writers
	writers []io.Writer

	// HMAC key for tamper evidence
	hmacKey []byte

	// State
	mutex         sync.Mutex
	lastEntryHash string
	sequenceNum   int64

	// Default fields added to all logs
	defaultFields map[string]interface{}
}

// SecurityLoggerConfig defines configuration for security logger
type SecurityLoggerConfig struct {
	// Writers where logs will be sent
	Writers []io.Writer

	// HMACKey for tamper evidence
	HMACKey []byte

	// DefaultFields added to all logs
	DefaultFields map[string]interface{}

	// Environment (prod, staging, etc.)
	Environment string

	// ApplicationName identifies the application
	ApplicationName string

	// InstanceID identifies the specific instance
	InstanceID string
}

// NewSecurityLogger creates a new security logger
func NewSecurityLogger(config *SecurityLoggerConfig) *SecurityLogger {
	if config == nil {
		config = &SecurityLoggerConfig{
			Writers: []io.Writer{os.Stdout},
			HMACKey: []byte("default-security-hmac-key"),
		}
	}

	// Create a default writer if none provided
	if len(config.Writers) == 0 {
		config.Writers = []io.Writer{os.Stdout}
	}

	// Generate a random key if not provided
	if len(config.HMACKey) == 0 {
		config.HMACKey = []byte("default-security-hmac-key")
	}

	// Initialize default fields
	if config.DefaultFields == nil {
		config.DefaultFields = make(map[string]interface{})
	}

	// Add environment information
	if config.Environment != "" {
		config.DefaultFields["environment"] = config.Environment
	}

	if config.ApplicationName != "" {
		config.DefaultFields["application"] = config.ApplicationName
	}

	if config.InstanceID != "" {
		config.DefaultFields["instance_id"] = config.InstanceID
	}

	return &SecurityLogger{
		writers:       config.Writers,
		hmacKey:       config.HMACKey,
		defaultFields: config.DefaultFields,
		lastEntryHash: "",
		sequenceNum:   0,
	}
}

// createLogEntry creates a new log entry with tamper-evidence
func (l *SecurityLogger) createLogEntry(
	level LogLevel,
	category LogCategory,
	message string,
	fields map[string]interface{},
) SecurityLogEntry {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	// Create entry
	entry := SecurityLogEntry{
		ID:                generateSecureID(),
		Timestamp:         time.Now().UTC(),
		Level:             level,
		Category:          category,
		Message:           message,
		PreviousEntryHash: l.lastEntryHash,
		SequenceNumber:    l.sequenceNum + 1,
		Details:           make(map[string]interface{}),
	}

	// Add the default fields
	for k, v := range l.defaultFields {
		entry.Details[k] = v
	}

	// Add the user-provided fields
	for k, v := range fields {
		switch k {
		case "user_id":
			if str, ok := v.(string); ok {
				entry.UserID = str
			}
		case "tenant_id":
			if str, ok := v.(string); ok {
				entry.TenantID = str
			}
		case "ip_address":
			if str, ok := v.(string); ok {
				entry.IPAddress = str
			}
		case "session_id":
			if str, ok := v.(string); ok {
				entry.SessionID = str
			}
		case "user_agent":
			if str, ok := v.(string); ok {
				entry.UserAgent = str
			}
		case "resource_id":
			if str, ok := v.(string); ok {
				entry.ResourceID = str
			}
		case "request_id":
			if str, ok := v.(string); ok {
				entry.RequestID = str
			}
		case "action":
			if str, ok := v.(string); ok {
				entry.Action = str
			}
		case "result":
			if str, ok := v.(string); ok {
				entry.Result = str
			}
		case "reason":
			if str, ok := v.(string); ok {
				entry.Reason = str
			}
		case "permissions":
			if strArr, ok := v.([]string); ok {
				entry.Permissions = strArr
			}
		case "roles":
			if strArr, ok := v.([]string); ok {
				entry.Roles = strArr
			}
		default:
			// Add to details
			entry.Details[k] = v
		}
	}

	// Generate entry hash for tamper evidence
	entryBytes, _ := json.Marshal(entry)
	entryHash := l.generateHMAC(string(entryBytes) + l.lastEntryHash)
	entry.EntryHash = entryHash

	// Update state
	l.lastEntryHash = entryHash
	l.sequenceNum++

	return entry
}

// generateHMAC creates a HMAC for tamper evidence
func (l *SecurityLogger) generateHMAC(data string) string {
	h := hmac.New(sha256.New, l.hmacKey)
	h.Write([]byte(data))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// writeLogEntry sends a log entry to all configured writers
func (l *SecurityLogger) writeLogEntry(entry SecurityLogEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	// Add newline for better readability
	data = append(data, '\n')

	// Write to all writers
	for _, w := range l.writers {
		if _, err := w.Write(data); err != nil {
			return err
		}
	}

	return nil
}

// Log logs a message with the specified level and category
func (l *SecurityLogger) Log(
	level LogLevel,
	category LogCategory,
	message string,
	fields map[string]interface{},
) error {
	entry := l.createLogEntry(level, category, message, fields)
	return l.writeLogEntry(entry)
}

// LogWithContext logs a message using context for additional fields
func (l *SecurityLogger) LogWithContext(
	ctx context.Context,
	level LogLevel,
	category LogCategory,
	message string,
	fields map[string]interface{},
) error {
	if fields == nil {
		fields = make(map[string]interface{})
	}

	// Extract fields from context if available
	if userID := ctx.Value(ContextKeyUserID); userID != nil {
		if id, ok := userID.(string); ok {
			fields["user_id"] = id
		}
	}

	if tenantID := ctx.Value(ContextKeyTenantID); tenantID != nil {
		if id, ok := tenantID.(string); ok {
			fields["tenant_id"] = id
		}
	}

	if requestID := ctx.Value(ContextKeyRequestID); requestID != nil {
		if id, ok := requestID.(string); ok {
			fields["request_id"] = id
		}
	}

	if ipAddress := ctx.Value(ContextKeyIPAddress); ipAddress != nil {
		if ip, ok := ipAddress.(string); ok {
			fields["ip_address"] = ip
		}
	}

	if sessionID := ctx.Value(ContextKeySessionID); sessionID != nil {
		if id, ok := sessionID.(string); ok {
			fields["session_id"] = id
		}
	}

	return l.Log(level, category, message, fields)
}

// Convenience methods

// Debug logs a debug-level message
func (l *SecurityLogger) Debug(category LogCategory, message string, fields map[string]interface{}) error {
	return l.Log(LogLevelDebug, category, message, fields)
}

// Info logs an info-level message
func (l *SecurityLogger) Info(category LogCategory, message string, fields map[string]interface{}) error {
	return l.Log(LogLevelInfo, category, message, fields)
}

// Warning logs a warning-level message
func (l *SecurityLogger) Warning(category LogCategory, message string, fields map[string]interface{}) error {
	return l.Log(LogLevelWarning, category, message, fields)
}

// Error logs an error-level message
func (l *SecurityLogger) Error(category LogCategory, message string, fields map[string]interface{}) error {
	return l.Log(LogLevelError, category, message, fields)
}

// Critical logs a critical-level message
func (l *SecurityLogger) Critical(category LogCategory, message string, fields map[string]interface{}) error {
	return l.Log(LogLevelCritical, category, message, fields)
}

// LogAuthSuccess logs a successful authentication
func (l *SecurityLogger) LogAuthSuccess(ctx context.Context, userID, tenantID, ipAddress string, fields map[string]interface{}) error {
	if fields == nil {
		fields = make(map[string]interface{})
	}

	fields["user_id"] = userID
	fields["tenant_id"] = tenantID
	fields["ip_address"] = ipAddress
	fields["action"] = "authentication"
	fields["result"] = "success"

	return l.LogWithContext(ctx, LogLevelInfo, LogCategoryAuth, "Authentication successful", fields)
}

// LogAuthFailure logs a failed authentication
func (l *SecurityLogger) LogAuthFailure(ctx context.Context, reason, userID, ipAddress string, fields map[string]interface{}) error {
	if fields == nil {
		fields = make(map[string]interface{})
	}

	fields["user_id"] = userID
	fields["ip_address"] = ipAddress
	fields["action"] = "authentication"
	fields["result"] = "failure"
	fields["reason"] = reason

	return l.LogWithContext(ctx, LogLevelWarning, LogCategoryAuth, "Authentication failed", fields)
}

// LogAccessDenied logs an access denial
func (l *SecurityLogger) LogAccessDenied(ctx context.Context, userID, resourceID string, reason string, fields map[string]interface{}) error {
	if fields == nil {
		fields = make(map[string]interface{})
	}

	fields["user_id"] = userID
	fields["resource_id"] = resourceID
	fields["action"] = "access"
	fields["result"] = "denied"
	fields["reason"] = reason

	return l.LogWithContext(ctx, LogLevelWarning, LogCategoryAccess, "Access denied", fields)
}

// LogDataAccess logs a data access event
func (l *SecurityLogger) LogDataAccess(ctx context.Context, userID, resourceID, action string, fields map[string]interface{}) error {
	if fields == nil {
		fields = make(map[string]interface{})
	}

	fields["user_id"] = userID
	fields["resource_id"] = resourceID
	fields["action"] = action
	fields["result"] = "success"

	return l.LogWithContext(ctx, LogLevelInfo, LogCategoryData, fmt.Sprintf("Data %s", action), fields)
}

// LogSensitiveAction logs a sensitive action
func (l *SecurityLogger) LogSensitiveAction(ctx context.Context, userID, action, result string, fields map[string]interface{}) error {
	if fields == nil {
		fields = make(map[string]interface{})
	}

	fields["user_id"] = userID
	fields["action"] = action
	fields["result"] = result

	level := LogLevelInfo
	if result != "success" {
		level = LogLevelWarning
	}

	return l.LogWithContext(ctx, level, LogCategoryAudit, fmt.Sprintf("Sensitive action: %s", action), fields)
}

// LogSecurityEvent logs a general security event
func (l *SecurityLogger) LogSecurityEvent(ctx context.Context, level LogLevel, message string, fields map[string]interface{}) error {
	return l.LogWithContext(ctx, level, LogCategorySecurity, message, fields)
}

// VerifyLogChain verifies the integrity of the log chain
func (l *SecurityLogger) VerifyLogChain(entries []SecurityLogEntry) (bool, int) {
	if len(entries) == 0 {
		return true, 0
	}

	// Check sequence numbers and hash chain
	previousHash := ""
	expectedSequence := int64(1)

	for i, entry := range entries {
		// Check sequence
		if entry.SequenceNumber != expectedSequence {
			return false, i
		}

		// Check previous hash
		if entry.PreviousEntryHash != previousHash {
			return false, i
		}

		// Check current hash
		entryCopy := entry
		entryCopy.EntryHash = ""
		entryBytes, _ := json.Marshal(entryCopy)
		expectedHash := l.generateHMAC(string(entryBytes) + previousHash)

		if entry.EntryHash != expectedHash {
			return false, i
		}

		// Update for next iteration
		previousHash = entry.EntryHash
		expectedSequence++
	}

	return true, -1
}

// Helper to generate a secure ID for log entries
func generateSecureID() string {
	return fmt.Sprintf("log-%d-%s", time.Now().UnixNano(), randomString(8))
}

// randomString generates a random string of specified length
func randomString(length int) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[time.Now().UnixNano()%62]
		time.Sleep(time.Nanosecond)
	}
	return string(b)
}
