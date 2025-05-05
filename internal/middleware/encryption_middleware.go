package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	"gobackend/internal/security"
	"gobackend/internal/utils"

	"github.com/gin-gonic/gin"
)

// SensitiveField represents a field that should be encrypted
type SensitiveField struct {
	ModelType  string   // The type of model this applies to
	FieldNames []string // Field names to encrypt
}

// EncryptionConfig defines the configuration for encryption middleware
type EncryptionConfig struct {
	Enabled         bool
	EncryptionSvc   *security.EncryptionService
	SensitiveFields map[string][]string // Map of model type to sensitive field names
}

// NewEncryptionMiddleware creates a new middleware for encrypting/decrypting sensitive data
func NewEncryptionMiddleware(encSvc *security.EncryptionService) gin.HandlerFunc {
	// Define which fields in which models should be encrypted
	sensitiveFields := map[string][]string{
		"User": {
			"TaxID",
			"SSN",
			"HealthData",
			"FinancialInfo",
		},
		"Customer": {
			"CreditCardNumber",
			"BankAccountNumber",
		},
		"Patient": {
			"MedicalRecordNumber",
			"DiagnosisInfo",
			"InsuranceNumber",
		},
	}

	config := &EncryptionConfig{
		Enabled:         true,
		EncryptionSvc:   encSvc,
		SensitiveFields: sensitiveFields,
	}

	return func(c *gin.Context) {
		if !config.Enabled {
			c.Next()
			return
		}

		// Process requests with JSON bodies for encryption
		if c.Request.Method == http.MethodPost || c.Request.Method == http.MethodPut || c.Request.Method == http.MethodPatch {
			processSensitiveRequestFields(c, config)
		}

		// Continue with the next handler
		c.Next()

		// Process responses to decrypt sensitive fields
		processSensitiveResponseFields(c, config)
	}
}

// processSensitiveRequestFields encrypts sensitive fields in request bodies
func processSensitiveRequestFields(c *gin.Context, config *EncryptionConfig) {
	// Check content type for JSON
	if !strings.Contains(c.GetHeader("Content-Type"), "application/json") {
		return
	}

	// Clone the request body since we can only read it once
	reqBody, err := utils.CloneRequestBody(c.Request)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Failed to read request body"})
		return
	}

	// Parse the request body based on the endpoint to identify model type
	modelType, err := determineModelType(c)
	if err != nil {
		// Just log and continue if we can't determine the model type
		c.Set("encryption_error", "Could not determine model type for encryption")
		c.Request.Body = reqBody // Restore original body
		return
	}

	// Get sensitive fields for this model
	fields, exists := config.SensitiveFields[modelType]
	if !exists || len(fields) == 0 {
		c.Request.Body = reqBody // Restore original body
		return
	}

	// Parse the request body
	var data map[string]interface{}
	if err := json.NewDecoder(reqBody).Decode(&data); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON format"})
		return
	}

	// Get record ID if it exists
	recordID := getRecordID(c, data)

	// Encrypt sensitive fields
	for _, field := range fields {
		if value, ok := data[field].(string); ok && value != "" {
			encrypted, err := config.EncryptionSvc.EncryptField(modelType, recordID, field, value)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Encryption failed"})
				return
			}
			data[field] = encrypted
		}
	}

	// Create new request body with encrypted fields
	newBody, err := json.Marshal(data)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to process request"})
		return
	}

	// Replace request body with encrypted version
	c.Request.Body = utils.CreateReadCloser(newBody)
	// Update Content-Length
	c.Request.ContentLength = int64(len(newBody))
}

// processSensitiveResponseFields decrypts sensitive fields in responses
func processSensitiveResponseFields(c *gin.Context, config *EncryptionConfig) {
	// Check if there's a response body to process
	if c.Writer.Size() <= 0 {
		return
	}

	// Check if we have a response writer that we can modify
	rw, ok := c.Writer.(gin.ResponseWriter)
	if !ok {
		return
	}

	// Get response data
	respData, exists := c.Get("response_data")
	if !exists {
		return
	}

	// Determine model type from response or request
	modelType, err := determineModelType(c)
	if err != nil {
		// Just log and continue if we can't determine the model type
		c.Set("encryption_error", "Could not determine model type for decryption")
		return
	}

	// Get sensitive fields for this model
	fields, exists := config.SensitiveFields[modelType]
	if !exists || len(fields) == 0 {
		return
	}

	// Process response data (could be a single object or a slice of objects)
	modified := false

	switch data := respData.(type) {
	case map[string]interface{}:
		// Single object
		recordID := getRecordIDFromMap(data)
		if recordID != "" {
			if processObject(data, modelType, recordID, fields, config, false) {
				modified = true
			}
		}
	case []map[string]interface{}:
		// Array of objects
		for _, item := range data {
			recordID := getRecordIDFromMap(item)
			if recordID != "" {
				if processObject(item, modelType, recordID, fields, config, false) {
					modified = true
				}
			}
		}
	}

	// If we modified the data, replace the response
	if modified {
		newResp, err := json.Marshal(respData)
		if err != nil {
			// Just log the error and continue with original response
			c.Set("encryption_error", "Failed to marshal modified response")
			return
		}

		// Clear the existing response
		rw.Header().Set("Content-Length", "0")
		// Write the new response
		rw.Header().Set("Content-Type", "application/json")
		rw.Header().Set("Content-Length", strconv.Itoa(len(newResp)))
		rw.WriteHeader(http.StatusOK) // We have to explicitly set the status code
		rw.Write(newResp)
	}
}

// processObject processes a single object for encryption or decryption
func processObject(obj map[string]interface{}, modelType, recordID string, fields []string, config *EncryptionConfig, encrypt bool) bool {
	modified := false
	for _, field := range fields {
		if value, ok := obj[field].(string); ok && value != "" {
			var newValue string
			var err error

			if encrypt {
				newValue, err = config.EncryptionSvc.EncryptField(modelType, recordID, field, value)
			} else {
				newValue, err = config.EncryptionSvc.DecryptField(modelType, recordID, field, value)
			}

			if err == nil {
				obj[field] = newValue
				modified = true
			}
		}
	}
	return modified
}

// determineModelType tries to determine the model type from the request URL
func determineModelType(c *gin.Context) (string, error) {
	path := c.FullPath()

	// Extract model name from path
	// Example: /api/v1/users -> User, /api/v1/customers -> Customer
	segments := strings.Split(path, "/")
	if len(segments) >= 3 {
		resourceName := segments[len(segments)-1]
		// Handle special cases like /resource/:id
		if strings.HasPrefix(resourceName, ":") {
			resourceName = segments[len(segments)-2]
		}
		// Convert to singular form and capitalize first letter
		resourceName = strings.TrimSuffix(resourceName, "s")
		if len(resourceName) > 0 {
			return strings.ToUpper(resourceName[:1]) + resourceName[1:], nil
		}
	}

	return "", errors.New("could not determine model type")
}

// getRecordID gets the record ID from context or data
func getRecordID(c *gin.Context, data map[string]interface{}) string {
	// Try to get ID from URL parameter first
	if id := c.Param("id"); id != "" {
		return id
	}

	// Try to get ID from the data
	return getRecordIDFromMap(data)
}

// getRecordIDFromMap extracts the record ID from a data map
func getRecordIDFromMap(data map[string]interface{}) string {
	// Check common ID field names
	idFields := []string{"id", "ID", "_id", "uuid", "UUID"}
	for _, field := range idFields {
		if id, ok := data[field].(string); ok && id != "" {
			return id
		}
		// Handle non-string IDs like numbers
		if id, ok := data[field]; ok {
			return reflect.ValueOf(id).String()
		}
	}
	return ""
}

// WithEncryptionContext sets encryption context in the request context
func WithEncryptionContext(ctx context.Context, modelType, recordID string) context.Context {
	return context.WithValue(ctx, "encryption_context", map[string]string{
		"model_type": modelType,
		"record_id":  recordID,
	})
}

// GetEncryptionContext gets encryption context from the request context
func GetEncryptionContext(ctx context.Context) (string, string, bool) {
	encCtx, ok := ctx.Value("encryption_context").(map[string]string)
	if !ok {
		return "", "", false
	}
	return encCtx["model_type"], encCtx["record_id"], true
}
