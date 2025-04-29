package api

import (
	"context"
	"net/http"
	"time"

	"gobackend/internal/observability"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// RequestLogger creates a middleware for logging HTTP requests
func RequestLogger(logger *observability.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Start timer
		start := time.Now()

		// Generate request ID if not present
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
			c.Header("X-Request-ID", requestID)
		}

		// Create context with request ID
		ctx := context.WithValue(c.Request.Context(), "request_id", requestID)
		c.Request = c.Request.WithContext(ctx)

		// Process request
		c.Next()

		// Calculate request duration
		duration := time.Since(start)

		// Log request details
		logger.APIRequest(
			ctx,
			c.Request.Method,
			c.Request.URL.Path,
			c.Writer.Status(),
			duration,
		)
	}
}

// RequestIDMiddleware adds a request ID to each request
func RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get request ID from header or generate a new one
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}

		// Set request ID in header
		c.Header("X-Request-ID", requestID)

		// Add request ID to context
		ctx := context.WithValue(c.Request.Context(), "request_id", requestID)
		c.Request = c.Request.WithContext(ctx)

		c.Next()
	}
}

// CORSMiddleware handles Cross-Origin Resource Sharing
func CORSMiddleware(allowedOrigins []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		// Check if the origin is allowed
		allowed := false
		for _, allowedOrigin := range allowedOrigins {
			if origin == allowedOrigin || allowedOrigin == "*" {
				allowed = true
				break
			}
		}

		if allowed {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, X-Request-ID")
			c.Header("Access-Control-Allow-Credentials", "true")
		}

		// Handle preflight requests
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
	Error   string `json:"error,omitempty"`
	TraceID string `json:"trace_id,omitempty"`
}

// ErrorHandler creates middleware for handling errors
func ErrorHandler(logger *observability.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		// Check if there are any errors
		if len(c.Errors) > 0 {
			err := c.Errors.Last().Err
			requestID, _ := c.Request.Context().Value("request_id").(string)

			// Log the error
			logger.Error("API Error", 
				err,
				observability.Field{Key: "method", Value: c.Request.Method}.ToZapField(),
				observability.Field{Key: "path", Value: c.Request.URL.Path}.ToZapField(),
				observability.Field{Key: "request_id", Value: requestID}.ToZapField(),
			)

			// Check if the response was already written
			if c.Writer.Written() {
				return
			}

			// Default to internal server error
			status := http.StatusInternalServerError
			message := "Internal Server Error"

			// Check for specific error types
			if ginErr, ok := err.(gin.Error); ok {
				if ginErr.IsType(gin.ErrorTypeBind) {
					status = http.StatusBadRequest
					message = "Invalid Request"
				}
			}

			// Create error response
			errorResponse := ErrorResponse{
				Status:  status,
				Message: message,
				TraceID: requestID,
			}

			// Add error details in development mode
			if gin.Mode() != gin.ReleaseMode {
				errorResponse.Error = err.Error()
			}

			c.JSON(status, errorResponse)
		}
	}
}
