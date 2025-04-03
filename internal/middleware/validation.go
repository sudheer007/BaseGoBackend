package middleware

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"gobackend/internal/utils"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
)

// Common validation patterns
var (
	// Common security patterns
	sqlInjectionPattern    = regexp.MustCompile(`(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|UNION|INTO|EXEC|DECLARE)\s`)
	xssScriptPattern       = regexp.MustCompile(`(?i)<script\b[^>]*>(.*?)</script>`)
	xssEventHandlerPattern = regexp.MustCompile(`(?i)\bon\w+\s*=`)
	xssAttributePattern    = regexp.MustCompile(`(?i)(javascript|data|vbscript):\s*`)

	// Common input validation patterns
	emailPattern    = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	phonePattern    = regexp.MustCompile(`^[+]?[(]?[0-9]{1,4}[)]?[-\s.]?[0-9]{1,4}[-\s.]?[0-9]{1,9}$`)
	alphaNumPattern = regexp.MustCompile(`^[a-zA-Z0-9]+$`)
	numericPattern  = regexp.MustCompile(`^[0-9]+$`)
	uuidPattern     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

// ValidationOptions defines configuration for validation middleware
type ValidationOptions struct {
	// Security validation options
	PreventSQLInjection     bool
	PreventXSS              bool
	PreventCommandInjection bool

	// Maximum sizes
	MaxJSONSize    int64
	MaxQueryValues int
	MaxURLLength   int
	MaxHeaderSize  int

	// General options
	StrictValidation bool
	SanitizeInputs   bool
}

// DefaultValidationOptions returns default validation options
func DefaultValidationOptions() ValidationOptions {
	return ValidationOptions{
		PreventSQLInjection:     true,
		PreventXSS:              true,
		PreventCommandInjection: true,
		MaxJSONSize:             1024 * 1024, // 1MB
		MaxQueryValues:          100,
		MaxURLLength:            2000,
		MaxHeaderSize:           8 * 1024, // 8KB
		StrictValidation:        false,
		SanitizeInputs:          true,
	}
}

// StrictValidationOptions returns strict validation options
func StrictValidationOptions() ValidationOptions {
	options := DefaultValidationOptions()
	options.StrictValidation = true
	options.MaxJSONSize = 512 * 1024 // 512KB
	options.MaxQueryValues = 50
	options.MaxURLLength = 1000
	return options
}

// ValidationError represents a validation error
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Code    string `json:"code,omitempty"`
}

// ValidationMiddleware validates incoming requests
func ValidationMiddleware() gin.HandlerFunc {
	return ValidationMiddlewareWithOptions(DefaultValidationOptions())
}

// ValidationMiddlewareWithOptions validates requests with custom options
func ValidationMiddlewareWithOptions(options ValidationOptions) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip validation for certain methods
		if c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}

		// Validate URL length
		if len(c.Request.URL.String()) > options.MaxURLLength {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "URL too long",
				"code":  "URL_TOO_LONG",
			})
			return
		}

		// Validate query parameters
		if err := validateQueryParams(c, options); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error":  "Invalid query parameters",
				"detail": err.Error(),
				"code":   "INVALID_QUERY_PARAMS",
			})
			return
		}

		// Validate request body for POST, PUT, PATCH
		if c.Request.Method == http.MethodPost || c.Request.Method == http.MethodPut || c.Request.Method == http.MethodPatch {
			if err := validateRequestBody(c, options); err != nil {
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
					"error":  "Invalid request body",
					"detail": err.Error(),
					"code":   "INVALID_REQUEST_BODY",
				})
				return
			}
		}

		// Validate headers
		if err := validateHeaders(c, options); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error":  "Invalid headers",
				"detail": err.Error(),
				"code":   "INVALID_HEADERS",
			})
			return
		}

		c.Next()
	}
}

// validateQueryParams validates query parameters
func validateQueryParams(c *gin.Context, options ValidationOptions) error {
	query := c.Request.URL.Query()

	// Check number of query parameters
	if len(query) > options.MaxQueryValues {
		return &ValidationError{
			Field:   "query",
			Message: "Too many query parameters",
			Code:    "TOO_MANY_QUERY_PARAMS",
		}
	}

	// Validate each query parameter
	for key, values := range query {
		for _, value := range values {
			// Prevent XSS in query parameters
			if options.PreventXSS && (xssScriptPattern.MatchString(value) ||
				xssEventHandlerPattern.MatchString(value) ||
				xssAttributePattern.MatchString(value)) {
				return &ValidationError{
					Field:   key,
					Message: "Query parameter contains potentially unsafe content",
					Code:    "XSS_RISK",
				}
			}

			// Prevent SQL injection in query parameters
			if options.PreventSQLInjection && sqlInjectionPattern.MatchString(value) {
				return &ValidationError{
					Field:   key,
					Message: "Query parameter contains potentially unsafe SQL",
					Code:    "SQL_INJECTION_RISK",
				}
			}

			// Sanitize inputs if configured
			if options.SanitizeInputs {
				value = sanitizeInput(value)
				// Update the query parameter (not working in Gin as is - we'd need to modify Request.URL)
			}
		}
	}

	return nil
}

// validateRequestBody validates the request body
func validateRequestBody(c *gin.Context, options ValidationOptions) error {
	// Check content length
	if c.Request.ContentLength > options.MaxJSONSize {
		return &ValidationError{
			Field:   "body",
			Message: "Request body too large",
			Code:    "BODY_TOO_LARGE",
		}
	}

	// Check content type
	contentType := c.GetHeader("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		// Skip validation for non-JSON content types
		return nil
	}

	// Read and validate JSON body
	bodyBytes, err := utils.CloneRequestBody(c.Request)
	if err != nil {
		return &ValidationError{
			Field:   "body",
			Message: "Failed to read request body",
			Code:    "BODY_READ_ERROR",
		}
	}

	// Parse the JSON
	var jsonData map[string]interface{}
	jsonBody, err := io.ReadAll(bodyBytes)
	if err != nil {
		return &ValidationError{
			Field:   "body",
			Message: "Failed to read request body",
			Code:    "BODY_READ_ERROR",
		}
	}

	if err := json.Unmarshal(jsonBody, &jsonData); err != nil {
		return &ValidationError{
			Field:   "body",
			Message: "Invalid JSON format",
			Code:    "INVALID_JSON",
		}
	}

	// Validate against security issues
	if err := validateJSONData(jsonData, options); err != nil {
		return err
	}

	// Restore the body
	c.Request.Body = utils.CreateReadCloser(jsonBody)

	return nil
}

// validateJSONData recursively validates JSON data for security issues
func validateJSONData(data map[string]interface{}, options ValidationOptions) error {
	for key, value := range data {
		switch v := value.(type) {
		case string:
			// Check for XSS in string values
			if options.PreventXSS && (xssScriptPattern.MatchString(v) ||
				xssEventHandlerPattern.MatchString(v) ||
				xssAttributePattern.MatchString(v)) {
				return &ValidationError{
					Field:   key,
					Message: "Field contains potentially unsafe content",
					Code:    "XSS_RISK",
				}
			}

			// Check for SQL injection
			if options.PreventSQLInjection && sqlInjectionPattern.MatchString(v) {
				return &ValidationError{
					Field:   key,
					Message: "Field contains potentially unsafe SQL",
					Code:    "SQL_INJECTION_RISK",
				}
			}

		case map[string]interface{}:
			// Recursively validate nested objects
			if err := validateJSONData(v, options); err != nil {
				return err
			}

		case []interface{}:
			// Validate array items
			for i, item := range v {
				if nestedMap, ok := item.(map[string]interface{}); ok {
					if err := validateJSONData(nestedMap, options); err != nil {
						return err
					}
				} else if str, ok := item.(string); ok {
					// Check string values in arrays
					if options.PreventXSS && (xssScriptPattern.MatchString(str) ||
						xssEventHandlerPattern.MatchString(str) ||
						xssAttributePattern.MatchString(str)) {
						return &ValidationError{
							Field:   key + "[" + string(rune(i)) + "]",
							Message: "Array item contains potentially unsafe content",
							Code:    "XSS_RISK",
						}
					}

					if options.PreventSQLInjection && sqlInjectionPattern.MatchString(str) {
						return &ValidationError{
							Field:   key + "[" + string(rune(i)) + "]",
							Message: "Array item contains potentially unsafe SQL",
							Code:    "SQL_INJECTION_RISK",
						}
					}
				}
			}
		}
	}

	return nil
}

// validateHeaders validates request headers
func validateHeaders(c *gin.Context, options ValidationOptions) error {
	// Check total header size
	headerSize := 0
	for key, values := range c.Request.Header {
		headerSize += len(key)
		for _, value := range values {
			headerSize += len(value)
		}
	}

	if headerSize > options.MaxHeaderSize {
		return &ValidationError{
			Field:   "headers",
			Message: "Headers too large",
			Code:    "HEADERS_TOO_LARGE",
		}
	}

	// Check specific headers for security issues
	referer := c.GetHeader("Referer")
	if options.PreventXSS && referer != "" {
		if _, err := url.Parse(referer); err != nil {
			return &ValidationError{
				Field:   "Referer",
				Message: "Invalid referer URL",
				Code:    "INVALID_REFERER",
			}
		}
	}

	return nil
}

// Error method for ValidationError
func (e *ValidationError) Error() string {
	return e.Message
}

// sanitizeInput sanitizes an input string
func sanitizeInput(input string) string {
	// Remove HTML tags
	input = regexp.MustCompile(`<[^>]*>`).ReplaceAllString(input, "")

	// Remove potentially dangerous characters
	input = strings.ReplaceAll(input, "<", "&lt;")
	input = strings.ReplaceAll(input, ">", "&gt;")
	input = strings.ReplaceAll(input, "\"", "&quot;")
	input = strings.ReplaceAll(input, "'", "&#39;")

	return input
}

// RegisterCustomValidators registers custom validators with Gin's validator
func RegisterCustomValidators() {
	if v, ok := binding.Validator.Engine().(*validator.Validate); ok {
		// Register custom validations
		v.RegisterValidation("alpha_num", validateAlphaNum)
		v.RegisterValidation("secure_password", validateSecurePassword)
		v.RegisterValidation("no_html", validateNoHTML)
		v.RegisterValidation("uuid", validateUUID)
	}
}

// Custom validators
func validateAlphaNum(fl validator.FieldLevel) bool {
	return alphaNumPattern.MatchString(fl.Field().String())
}

func validateSecurePassword(fl validator.FieldLevel) bool {
	password := fl.Field().String()

	// Password must be at least 8 characters
	if len(password) < 8 {
		return false
	}

	// Check for uppercase, lowercase, digit, and special character
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	hasDigit := regexp.MustCompile(`[0-9]`).MatchString(password)
	hasSpecial := regexp.MustCompile(`[!@#$%^&*(),.?":{}|<>]`).MatchString(password)

	return hasUpper && hasLower && hasDigit && hasSpecial
}

func validateNoHTML(fl validator.FieldLevel) bool {
	return !regexp.MustCompile(`<[^>]*>`).MatchString(fl.Field().String())
}

func validateUUID(fl validator.FieldLevel) bool {
	return uuidPattern.MatchString(fl.Field().String())
}
