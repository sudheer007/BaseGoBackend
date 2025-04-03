package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"gobackend/internal/models"
	"gobackend/internal/security"
)

// Maximum request/response size to log
const maxBodyLogSize = 10 * 1024 // 10KB

// AuditConfig defines configuration options for the audit middleware
type AuditConfig struct {
	// Enabled determines if audit logging is enabled
	Enabled bool

	// LogRequests determines if request bodies should be logged
	LogRequests bool

	// LogResponses determines if response bodies should be logged
	LogResponses bool

	// ExcludedPaths are URL paths that will not be audited
	ExcludedPaths []string

	// SensitiveHeaderFields are header fields that will be redacted in logs
	SensitiveHeaderFields []string

	// SensitiveBodyFields are body fields that will be redacted in logs
	SensitiveBodyFields []string

	// Logger is the security logger to use
	Logger *security.SecurityLogger
}

// DefaultAuditConfig returns a default audit configuration
func DefaultAuditConfig() *AuditConfig {
	return &AuditConfig{
		Enabled:      true,
		LogRequests:  true,
		LogResponses: true,
		ExcludedPaths: []string{
			"/health",
			"/metrics",
			"/livez",
			"/readyz",
			"/favicon.ico",
		},
		SensitiveHeaderFields: []string{
			"Authorization",
			"X-API-Key",
			"Cookie",
			"Set-Cookie",
		},
		SensitiveBodyFields: []string{
			"password",
			"token",
			"secret",
			"credential",
			"api_key",
			"credit_card",
			"ssn",
			"social_security",
		},
	}
}

// StrictAuditConfig returns a stricter audit configuration
func StrictAuditConfig() *AuditConfig {
	config := DefaultAuditConfig()
	// Add more paths to exclude or sensitive fields to redact
	return config
}

// bodyLogWriter is a gin.ResponseWriter that captures the response body
type bodyLogWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

// Write captures the response body before writing it to the client
func (w *bodyLogWriter) Write(b []byte) (int, error) {
	// Only record up to maxBodyLogSize
	if w.body.Len() < maxBodyLogSize {
		// Calculate remaining capacity
		remaining := maxBodyLogSize - w.body.Len()
		if remaining > 0 {
			if len(b) <= remaining {
				w.body.Write(b)
			} else {
				w.body.Write(b[:remaining])
				w.body.WriteString("... (truncated)")
			}
		}
	}
	return w.ResponseWriter.Write(b)
}

// AuditMiddleware creates a middleware that logs all API requests and responses
func AuditMiddleware(config *AuditConfig) gin.HandlerFunc {
	if config == nil {
		config = DefaultAuditConfig()
	}

	if !config.Enabled {
		// Return no-op middleware if not enabled
		return func(c *gin.Context) {
			c.Next()
		}
	}

	// Create a default logger if not provided
	if config.Logger == nil {
		config.Logger = security.NewSecurityLogger(nil)
	}

	return func(c *gin.Context) {
		// Skip excluded paths
		for _, path := range config.ExcludedPaths {
			if strings.HasPrefix(c.Request.URL.Path, path) {
				c.Next()
				return
			}
		}

		start := time.Now()
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = fmt.Sprintf("req-%d-%d", time.Now().UnixNano(), time.Now().Unix())
			c.Request.Header.Set("X-Request-ID", requestID)
		}

		// Set request ID in context
		c.Set(string(security.ContextKeyRequestID), requestID)

		// Extract user and tenant IDs if available
		userID, _ := c.Get(string(security.ContextKeyUserID))
		tenantID, _ := c.Get(string(security.ContextKeyTenantID))

		// Log request
		var requestBody []byte
		var err error

		// Only capture the request body if configured and the method is not GET
		if config.LogRequests && c.Request.Method != http.MethodGet && c.Request.Body != nil {
			requestBody, err = io.ReadAll(c.Request.Body)
			if err != nil {
				config.Logger.Warning(
					security.LogCategoryAudit,
					"Failed to read request body",
					map[string]interface{}{
						"request_id": requestID,
						"error":      err.Error(),
					},
				)
			}

			// Restore the request body for further processing
			c.Request.Body = io.NopCloser(bytes.NewBuffer(requestBody))
		}

		// Redact sensitive information from request body
		var redactedRequestBody map[string]interface{}
		if len(requestBody) > 0 {
			if err = json.Unmarshal(requestBody, &redactedRequestBody); err == nil {
				redactSensitiveData(redactedRequestBody, config.SensitiveBodyFields)
			}
		}

		// Create headers map and redact sensitive headers
		headers := make(map[string]string)
		for name, values := range c.Request.Header {
			if len(values) > 0 {
				value := values[0]
				for _, sensitiveField := range config.SensitiveHeaderFields {
					if strings.EqualFold(name, sensitiveField) {
						value = "[REDACTED]"
						break
					}
				}
				headers[name] = value
			}
		}

		// Log the request
		auditFields := map[string]interface{}{
			"request_id":   requestID,
			"method":       c.Request.Method,
			"path":         c.Request.URL.Path,
			"query":        c.Request.URL.RawQuery,
			"client_ip":    c.ClientIP(),
			"host":         c.Request.Host,
			"headers":      headers,
			"protocol":     c.Request.Proto,
			"request_size": c.Request.ContentLength,
			"content_type": c.ContentType(),
			"user_agent":   c.Request.UserAgent(),
		}

		// Add user and tenant IDs if available
		if userID != nil {
			auditFields["user_id"] = userID
		}
		if tenantID != nil {
			auditFields["tenant_id"] = tenantID
		}

		// Only add the body if we have one
		if redactedRequestBody != nil {
			auditFields["request_body"] = redactedRequestBody
		}

		// Log the request
		config.Logger.Info(
			security.LogCategoryAudit,
			"API Request",
			auditFields,
		)

		// Capture the response body if configured
		var responseBodyWriter *bodyLogWriter
		if config.LogResponses {
			responseBodyWriter = &bodyLogWriter{
				ResponseWriter: c.Writer,
				body:           bytes.NewBuffer(nil),
			}
			c.Writer = responseBodyWriter
		}

		// Process the request
		c.Next()

		// Log response after request is processed
		duration := time.Since(start)
		statusCode := c.Writer.Status()

		// Prepare response audit fields
		responseFields := map[string]interface{}{
			"request_id":    requestID,
			"method":        c.Request.Method,
			"path":          c.Request.URL.Path,
			"status":        statusCode,
			"duration_ms":   duration.Milliseconds(),
			"client_ip":     c.ClientIP(),
			"user_agent":    c.Request.UserAgent(),
			"response_size": c.Writer.Size(),
		}

		// Add user and tenant IDs if available
		if userID != nil {
			responseFields["user_id"] = userID
		}
		if tenantID != nil {
			responseFields["tenant_id"] = tenantID
		}

		// Add response body if captured
		if config.LogResponses && responseBodyWriter != nil && responseBodyWriter.body.Len() > 0 {
			// Try to parse JSON response
			var responseBody map[string]interface{}
			responseBodyBytes := responseBodyWriter.body.Bytes()

			if json.Unmarshal(responseBodyBytes, &responseBody) == nil {
				// Redact sensitive fields from response
				redactSensitiveData(responseBody, config.SensitiveBodyFields)
				responseFields["response_body"] = responseBody
			} else {
				// Unable to parse as JSON, use raw string
				responseStr := string(responseBodyBytes)
				if len(responseStr) > maxBodyLogSize {
					responseStr = responseStr[:maxBodyLogSize] + "... (truncated)"
				}
				responseFields["response_body"] = responseStr
			}
		}

		// Add error information if there are any
		if len(c.Errors) > 0 {
			errorMessages := make([]string, len(c.Errors))
			for i, err := range c.Errors {
				errorMessages[i] = err.Error()
			}
			responseFields["errors"] = errorMessages
		}

		// Determine log level based on status code
		var level security.LogLevel
		var message string

		switch {
		case statusCode >= 500:
			level = security.LogLevelError
			message = "API Server Error"
		case statusCode >= 400:
			level = security.LogLevelWarning
			message = "API Client Error"
		default:
			level = security.LogLevelInfo
			message = "API Response"
		}

		// Log the response
		config.Logger.Log(
			level,
			security.LogCategoryAudit,
			message,
			responseFields,
		)

		// If this is unauthorized, also log a security event
		if statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden {
			securityFields := map[string]interface{}{
				"request_id":  requestID,
				"method":      c.Request.Method,
				"path":        c.Request.URL.Path,
				"client_ip":   c.ClientIP(),
				"status_code": statusCode,
			}

			// Add user and tenant IDs if available
			if userID != nil {
				securityFields["user_id"] = userID
			}
			if tenantID != nil {
				securityFields["tenant_id"] = tenantID
			}

			message := "Forbidden Access Attempt"
			if statusCode == http.StatusUnauthorized {
				message = "Unauthorized Access Attempt"
			}

			config.Logger.Warning(
				security.LogCategorySecurity,
				message,
				securityFields,
			)
		}
	}
}

// redactSensitiveData replaces sensitive fields with "[REDACTED]"
func redactSensitiveData(data map[string]interface{}, sensitiveFields []string) {
	for key, value := range data {
		// Check if this key is sensitive
		isSensitive := false
		keyLower := strings.ToLower(key)

		for _, field := range sensitiveFields {
			if strings.Contains(keyLower, strings.ToLower(field)) {
				isSensitive = true
				break
			}
		}

		if isSensitive {
			// Redact this field
			data[key] = "[REDACTED]"
		} else {
			// Check nested structures
			switch v := value.(type) {
			case map[string]interface{}:
				redactSensitiveData(v, sensitiveFields)
			case []interface{}:
				for _, item := range v {
					if mapItem, ok := item.(map[string]interface{}); ok {
						redactSensitiveData(mapItem, sensitiveFields)
					}
				}
			}
		}
	}
}

// AuditLog creates an audit log entry
func AuditLog(c *gin.Context, action string, details map[string]interface{}) {
	// Get the security logger
	loggerInterface, exists := c.Get("security_logger")
	if !exists {
		// No logger available
		return
	}

	logger, ok := loggerInterface.(*security.SecurityLogger)
	if !ok {
		// Invalid logger type
		return
	}

	// Get request details
	requestID := c.GetHeader("X-Request-ID")
	if requestID == "" {
		if reqID, exists := c.Get(string(security.ContextKeyRequestID)); exists {
			if id, ok := reqID.(string); ok {
				requestID = id
			}
		}
	}

	// Prepare audit fields
	auditFields := map[string]interface{}{
		"request_id": requestID,
		"method":     c.Request.Method,
		"path":       c.Request.URL.Path,
		"client_ip":  c.ClientIP(),
		"action":     action,
	}

	// Add user and tenant IDs if available
	userID, hasUserID := c.Get(string(security.ContextKeyUserID))
	if hasUserID {
		auditFields["user_id"] = userID
	}

	tenantID, hasTenantID := c.Get(string(security.ContextKeyTenantID))
	if hasTenantID {
		auditFields["tenant_id"] = tenantID
	}

	// Add details
	for k, v := range details {
		auditFields[k] = v
	}

	// Log the action
	logger.Info(security.LogCategoryAudit, action, auditFields)
}

// AuditRecordModel creates a database audit record model
func AuditRecordModel(c *gin.Context, action, resourceType, resourceID string, before, after interface{}) *models.AuditLog {
	var userIDStr, tenantIDStr string

	// Extract user and tenant IDs
	if userIDValue, hasUserID := c.Get(string(security.ContextKeyUserID)); hasUserID {
		if idStr, ok := userIDValue.(string); ok {
			userIDStr = idStr
		}
	}

	if tenantIDValue, hasTenantID := c.Get(string(security.ContextKeyTenantID)); hasTenantID {
		if idStr, ok := tenantIDValue.(string); ok {
			tenantIDStr = idStr
		}
	}

	// Parse IDs to UUID
	var userID, tenantID uuid.UUID
	if userIDStr != "" {
		var err error
		userID, err = uuid.Parse(userIDStr)
		if err != nil {
			// Log error but continue
			userID = uuid.Nil
		}
	}

	if tenantIDStr != "" {
		var err error
		tenantID, err = uuid.Parse(tenantIDStr)
		if err != nil {
			// Log error but continue
			tenantID = uuid.Nil
		}
	}

	// Convert action string to AuditAction
	auditAction := models.AuditAction(action)

	// Create audit record
	record := models.NewAuditLog(tenantID, userID, auditAction, resourceType, resourceID)
	record.IPAddress = c.ClientIP()
	record.UserAgent = c.Request.UserAgent()

	// Add old/new state if provided
	if before != nil {
		record.SetOldValue(before)
	}

	if after != nil {
		record.SetNewValue(after)
	}

	return record
}
