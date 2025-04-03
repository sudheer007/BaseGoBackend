package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/microcosm-cc/bluemonday"
)

// Common regex patterns for malicious content
var (
	// SQL Injection patterns
	sqlInjectionRegex = regexp.MustCompile(`(?i)('|"|--|#|/\*|\*/|;|\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|UNION|INTO|LOAD_FILE|OUTFILE)\b)`)

	// XSS patterns for bypass attempts
	xssRegex = regexp.MustCompile(`(?i)(javascript:|data:text\/html|<script|<img|<iframe|<svg|<embed|<object|onerror|onload|onclick|onfocus|onmouseover)`)

	// Path traversal
	pathTraversalRegex = regexp.MustCompile(`\.\.\/|\.\.\\`)

	// Command injection patterns (using raw string literal)
	commandInjectionRegex = regexp.MustCompile(`\$\(|` + "`" + `|\&\&|\|\||;\s*\w+|\beval\b|\bexec\b|\bsystem\b|\bpassthru\b|\bshell_exec\b`)

	// NoSQL injection patterns
	noSQLInjectionRegex = regexp.MustCompile(`\$where|\$regex|\$ne|\$gt|\$lt|\$gte|\$lte|\$eq|\$elemMatch|\$nin|\$in|\$all|\$or|\$and|\$not`)

	// XML external entity (XXE) patterns
	xxeRegex = regexp.MustCompile(`<!ENTITY|<!DOCTYPE`)
)

// SanitizeConfig defines configuration options for the input sanitization middleware
type SanitizeConfig struct {
	// EnableXSSProtection enables XSS sanitization
	EnableXSSProtection bool

	// EnableSQLInjectionProtection enables SQL injection detection
	EnableSQLInjectionProtection bool

	// EnableNoSQLInjectionProtection enables NoSQL injection detection
	EnableNoSQLInjectionProtection bool

	// EnablePathTraversalProtection enables path traversal detection
	EnablePathTraversalProtection bool

	// EnableCommandInjectionProtection enables command injection detection
	EnableCommandInjectionProtection bool

	// EnableXXEProtection enables XXE protection
	EnableXXEProtection bool

	// StrictMode will reject requests with suspicious patterns rather than sanitizing them
	StrictMode bool

	// ExcludedPaths are URL paths that will not be sanitized
	ExcludedPaths []string

	// MaxBodySize is the maximum size of the request body to sanitize (in bytes)
	MaxBodySize int64

	// Logger used for logging sanitization actions
	Logger interface {
		Warning(category, message string, fields map[string]interface{}) error
	}
}

// DefaultSanitizeConfig returns a default sanitization configuration
func DefaultSanitizeConfig() *SanitizeConfig {
	return &SanitizeConfig{
		EnableXSSProtection:              true,
		EnableSQLInjectionProtection:     true,
		EnableNoSQLInjectionProtection:   true,
		EnablePathTraversalProtection:    true,
		EnableCommandInjectionProtection: true,
		EnableXXEProtection:              true,
		StrictMode:                       false,
		MaxBodySize:                      10 * 1024 * 1024, // 10 MB
		ExcludedPaths: []string{
			"/health",
			"/metrics",
			"/livez",
			"/readyz",
		},
	}
}

// StrictSanitizeConfig returns a stricter sanitization configuration
func StrictSanitizeConfig() *SanitizeConfig {
	config := DefaultSanitizeConfig()
	config.StrictMode = true
	return config
}

// SanitizeMiddleware creates a middleware that sanitizes input to prevent various injection attacks
func SanitizeMiddleware(config *SanitizeConfig) gin.HandlerFunc {
	if config == nil {
		config = DefaultSanitizeConfig()
	}

	// Create a bluemonday HTML sanitization policy
	htmlPolicy := bluemonday.UGCPolicy()

	return func(c *gin.Context) {
		// Skip excluded paths
		for _, path := range config.ExcludedPaths {
			if strings.HasPrefix(c.Request.URL.Path, path) {
				c.Next()
				return
			}
		}

		// Check query parameters
		if err := sanitizeQueryParams(c, config, htmlPolicy); err != nil {
			abortWithSanitizationError(c, config, "query_params", err.Error())
			return
		}

		// Check URL path parameters
		if err := sanitizeURLParams(c, config, htmlPolicy); err != nil {
			abortWithSanitizationError(c, config, "url_params", err.Error())
			return
		}

		// Check headers (except for some standard ones)
		if err := sanitizeHeaders(c, config, htmlPolicy); err != nil {
			abortWithSanitizationError(c, config, "headers", err.Error())
			return
		}

		// Check and sanitize the request body for specific content types
		contentType := c.GetHeader("Content-Type")
		if strings.Contains(contentType, "application/json") {
			if err := sanitizeJSONBody(c, config, htmlPolicy); err != nil {
				abortWithSanitizationError(c, config, "json_body", err.Error())
				return
			}
		} else if strings.Contains(contentType, "application/x-www-form-urlencoded") {
			if err := sanitizeFormBody(c, config, htmlPolicy); err != nil {
				abortWithSanitizationError(c, config, "form_body", err.Error())
				return
			}
		} else if strings.Contains(contentType, "multipart/form-data") {
			// For multipart/form-data, we only sanitize the form values, not the files
			if err := sanitizeFormBody(c, config, htmlPolicy); err != nil {
				abortWithSanitizationError(c, config, "multipart_form", err.Error())
				return
			}
		}

		c.Next()
	}
}

// sanitizeQueryParams sanitizes query parameters
func sanitizeQueryParams(c *gin.Context, config *SanitizeConfig, policy *bluemonday.Policy) error {
	query := c.Request.URL.Query()
	for key, values := range query {
		for i, value := range values {
			sanitized, err := sanitizeString(value, config, policy)
			if err != nil {
				return err
			}
			values[i] = sanitized
		}
		query[key] = values
	}
	c.Request.URL.RawQuery = query.Encode()
	return nil
}

// sanitizeURLParams sanitizes URL path parameters
func sanitizeURLParams(c *gin.Context, config *SanitizeConfig, policy *bluemonday.Policy) error {
	params := c.Params
	for _, param := range params {
		sanitized, err := sanitizeString(param.Value, config, policy)
		if err != nil {
			return err
		}
		// We can't directly modify Gin's params, but we can set custom attributes
		c.Set("sanitized_"+param.Key, sanitized)
	}
	return nil
}

// sanitizeHeaders sanitizes HTTP headers
func sanitizeHeaders(c *gin.Context, config *SanitizeConfig, policy *bluemonday.Policy) error {
	// Skip sanitizing some standard headers
	skipHeaders := map[string]bool{
		"Authorization":  true,
		"Content-Type":   true,
		"Accept":         true,
		"User-Agent":     true,
		"Content-Length": true,
		"Host":           true,
	}

	for key, values := range c.Request.Header {
		if skipHeaders[key] {
			continue
		}

		for i, value := range values {
			sanitized, err := sanitizeString(value, config, policy)
			if err != nil {
				return err
			}
			values[i] = sanitized
		}
		c.Request.Header[key] = values
	}
	return nil
}

// sanitizeJSONBody sanitizes a JSON request body
func sanitizeJSONBody(c *gin.Context, config *SanitizeConfig, policy *bluemonday.Policy) error {
	// Limit the size of the request body
	if c.Request.ContentLength > config.MaxBodySize {
		return &SanitizationError{Message: "Request body exceeds maximum size limit"}
	}

	// Read the body
	var bodyBytes []byte
	if c.Request.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(io.LimitReader(c.Request.Body, config.MaxBodySize))
		if err != nil {
			return err
		}
		c.Request.Body.Close()
	}

	// If body is empty, nothing to do
	if len(bodyBytes) == 0 {
		c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		return nil
	}

	// Parse JSON
	var data interface{}
	if err := json.Unmarshal(bodyBytes, &data); err != nil {
		// Not valid JSON, restore original body
		c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		return &SanitizationError{Message: "Invalid JSON format"}
	}

	// Sanitize the parsed data
	sanitized, err := sanitizeValue(data, config, policy)
	if err != nil {
		c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		return err
	}

	// Marshal the sanitized data back to JSON
	newBody, err := json.Marshal(sanitized)
	if err != nil {
		c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		return &SanitizationError{Message: "Failed to marshal sanitized JSON"}
	}

	// Set the sanitized body back to the request
	c.Request.Body = io.NopCloser(bytes.NewBuffer(newBody))
	c.Request.ContentLength = int64(len(newBody))

	return nil
}

// sanitizeFormBody sanitizes form data
func sanitizeFormBody(c *gin.Context, config *SanitizeConfig, policy *bluemonday.Policy) error {
	// Check content length limit
	if c.Request.ContentLength > config.MaxBodySize {
		return &SanitizationError{Message: "Request body exceeds maximum size limit"}
	}

	// Parse the form if not already parsed
	if err := c.Request.ParseForm(); err != nil {
		return &SanitizationError{Message: "Failed to parse form data"}
	}

	// Sanitize form values
	for key, values := range c.Request.Form {
		for i, value := range values {
			sanitized, err := sanitizeString(value, config, policy)
			if err != nil {
				return err
			}
			values[i] = sanitized
		}
		c.Request.Form[key] = values
	}

	// Also check POST form values
	for key, values := range c.Request.PostForm {
		for i, value := range values {
			sanitized, err := sanitizeString(value, config, policy)
			if err != nil {
				return err
			}
			values[i] = sanitized
		}
		c.Request.PostForm[key] = values
	}

	return nil
}

// sanitizeValue recursively sanitizes a value (map, slice, or primitive)
func sanitizeValue(value interface{}, config *SanitizeConfig, policy *bluemonday.Policy) (interface{}, error) {
	switch v := value.(type) {
	case map[string]interface{}:
		// Handle maps recursively
		result := make(map[string]interface{})
		for key, val := range v {
			// Sanitize the key
			sanitizedKey, err := sanitizeString(key, config, policy)
			if err != nil {
				return nil, err
			}

			// Sanitize the value recursively
			sanitizedVal, err := sanitizeValue(val, config, policy)
			if err != nil {
				return nil, err
			}

			result[sanitizedKey] = sanitizedVal
		}
		return result, nil

	case []interface{}:
		// Handle arrays recursively
		result := make([]interface{}, len(v))
		for i, val := range v {
			sanitizedVal, err := sanitizeValue(val, config, policy)
			if err != nil {
				return nil, err
			}
			result[i] = sanitizedVal
		}
		return result, nil

	case string:
		// Handle strings
		return sanitizeString(v, config, policy)

	default:
		// Other types (numbers, booleans, null) are passed through unchanged
		return v, nil
	}
}

// sanitizeString sanitizes a string according to the configuration
func sanitizeString(value string, config *SanitizeConfig, policy *bluemonday.Policy) (string, error) {
	// Check for SQL injection
	if config.EnableSQLInjectionProtection && sqlInjectionRegex.MatchString(value) {
		if config.StrictMode {
			return "", &SanitizationError{Type: "sql_injection", Message: "Potential SQL injection detected"}
		}
		// Log the attempt
		if config.Logger != nil {
			config.Logger.Warning("SecuritySanitize", "SQL injection attempt detected", map[string]interface{}{
				"value": value,
			})
		}
		value = sqlInjectionRegex.ReplaceAllString(value, "")
	}

	// Check for NoSQL injection
	if config.EnableNoSQLInjectionProtection && noSQLInjectionRegex.MatchString(value) {
		if config.StrictMode {
			return "", &SanitizationError{Type: "nosql_injection", Message: "Potential NoSQL injection detected"}
		}
		// Log the attempt
		if config.Logger != nil {
			config.Logger.Warning("SecuritySanitize", "NoSQL injection attempt detected", map[string]interface{}{
				"value": value,
			})
		}
		value = noSQLInjectionRegex.ReplaceAllString(value, "")
	}

	// Check for path traversal
	if config.EnablePathTraversalProtection && pathTraversalRegex.MatchString(value) {
		if config.StrictMode {
			return "", &SanitizationError{Type: "path_traversal", Message: "Path traversal attempt detected"}
		}
		// Log the attempt
		if config.Logger != nil {
			config.Logger.Warning("SecuritySanitize", "Path traversal attempt detected", map[string]interface{}{
				"value": value,
			})
		}
		value = pathTraversalRegex.ReplaceAllString(value, "")
	}

	// Check for command injection
	if config.EnableCommandInjectionProtection && commandInjectionRegex.MatchString(value) {
		if config.StrictMode {
			return "", &SanitizationError{Type: "command_injection", Message: "Command injection attempt detected"}
		}
		// Log the attempt
		if config.Logger != nil {
			config.Logger.Warning("SecuritySanitize", "Command injection attempt detected", map[string]interface{}{
				"value": value,
			})
		}
		value = commandInjectionRegex.ReplaceAllString(value, "")
	}

	// Check for XXE
	if config.EnableXXEProtection && xxeRegex.MatchString(value) {
		if config.StrictMode {
			return "", &SanitizationError{Type: "xxe", Message: "XXE attempt detected"}
		}
		// Log the attempt
		if config.Logger != nil {
			config.Logger.Warning("SecuritySanitize", "XXE attempt detected", map[string]interface{}{
				"value": value,
			})
		}
		value = xxeRegex.ReplaceAllString(value, "")
	}

	// Apply XSS protection
	if config.EnableXSSProtection {
		// Check for obvious XSS patterns first (which might be missed by bluemonday)
		if xssRegex.MatchString(value) {
			if config.StrictMode {
				return "", &SanitizationError{Type: "xss", Message: "XSS attempt detected"}
			}
			// Log the attempt
			if config.Logger != nil {
				config.Logger.Warning("SecuritySanitize", "XSS attempt detected", map[string]interface{}{
					"value": value,
				})
			}
			value = xssRegex.ReplaceAllString(value, "")
		}

		// Apply HTML sanitization
		value = policy.Sanitize(value)
	}

	return value, nil
}

// SanitizationError represents an error encountered during sanitization
type SanitizationError struct {
	Type    string
	Message string
}

// Error implements the error interface
func (e *SanitizationError) Error() string {
	if e.Type != "" {
		return e.Type + ": " + e.Message
	}
	return e.Message
}

// abortWithSanitizationError ends the request with an error
func abortWithSanitizationError(c *gin.Context, config *SanitizeConfig, location, message string) {
	status := http.StatusBadRequest

	// Log the attempt
	if config.Logger != nil {
		config.Logger.Warning("SecuritySanitize", "Input sanitization failed", map[string]interface{}{
			"location": location,
			"message":  message,
			"ip":       c.ClientIP(),
			"path":     c.Request.URL.Path,
			"method":   c.Request.Method,
		})
	}

	c.AbortWithStatusJSON(status, gin.H{
		"error":   "Invalid input",
		"message": "The request contains potentially malicious content",
	})
}
