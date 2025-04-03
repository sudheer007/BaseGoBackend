package middleware

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// CORSConfig defines configuration for CORS middleware
type CORSConfig struct {
	// AllowedOrigins is a list of allowed origins. Use "*" for wildcard.
	AllowedOrigins []string

	// AllowedMethods is a list of allowed HTTP methods.
	AllowedMethods []string

	// AllowedHeaders is a list of allowed headers.
	AllowedHeaders []string

	// ExposeHeaders is a list of headers to expose to the client.
	ExposeHeaders []string

	// AllowCredentials indicates whether credentials (cookies, auth) are allowed.
	AllowCredentials bool

	// AllowWildcard allows wildcard origin "*". Use with caution.
	AllowWildcard bool

	// AllowBrowserExtensions allows requests from browser extensions.
	AllowBrowserExtensions bool

	// MaxAge indicates how long the results of a preflight request can be cached.
	MaxAge time.Duration

	// OptionsPassthrough allows OPTIONS requests to be passed to the handler.
	OptionsPassthrough bool
}

// DefaultCORSConfig returns a reasonable default CORS configuration
func DefaultCORSConfig() *CORSConfig {
	return &CORSConfig{
		AllowedOrigins:   []string{"http://localhost:3000"}, // Default for local development
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Request-ID"},
		ExposeHeaders:    []string{"Content-Length", "X-Request-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"},
		AllowCredentials: true,
		AllowWildcard:    false,
		MaxAge:           12 * time.Hour,
	}
}

// PermissiveCORSConfig returns a permissive CORS configuration (use with caution)
func PermissiveCORSConfig() *CORSConfig {
	return &CORSConfig{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Request-ID"},
		ExposeHeaders:    []string{"Content-Length", "X-Request-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"},
		AllowCredentials: true,
		AllowWildcard:    true,
		MaxAge:           12 * time.Hour,
	}
}

// CORSMiddleware creates a middleware to handle CORS requests
func CORSMiddleware(config *CORSConfig) gin.HandlerFunc {
	if config == nil {
		config = DefaultCORSConfig()
	}

	// Prepare allowed headers string
	allowHeaders := strings.Join(config.AllowedHeaders, ", ")
	if allowHeaders == "" {
		allowHeaders = "Origin, Content-Type, Accept"
	}

	// Prepare exposed headers string
	exposeHeaders := strings.Join(config.ExposeHeaders, ", ")

	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		allowOrigin := ""

		// Check if origin is allowed
		allowed := false
		for _, o := range config.AllowedOrigins {
			if o == "*" && config.AllowWildcard {
				allowOrigin = "*"
				allowed = true
				break
			} else if strings.EqualFold(o, origin) {
				allowOrigin = origin
				allowed = true
				break
			}
		}

		// Handle browser extensions if allowed
		if !allowed && config.AllowBrowserExtensions && strings.HasPrefix(origin, "chrome-extension://") || strings.HasPrefix(origin, "moz-extension://") {
			allowOrigin = origin
			allowed = true
		}

		if allowed {
			c.Writer.Header().Set("Access-Control-Allow-Origin", allowOrigin)
			if config.AllowCredentials {
				c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
			}
		}

		// Handle preflight requests (OPTIONS)
		if c.Request.Method == http.MethodOptions {
			if allowed {
				c.Writer.Header().Set("Access-Control-Allow-Methods", strings.Join(config.AllowedMethods, ", "))
				c.Writer.Header().Set("Access-Control-Allow-Headers", allowHeaders)
				if config.MaxAge > 0 {
					c.Writer.Header().Set("Access-Control-Max-Age", config.MaxAge.String())
				}
			}

			if !config.OptionsPassthrough {
				c.AbortWithStatus(http.StatusNoContent)
				return
			}
		}

		// Expose headers
		if allowed && exposeHeaders != "" {
			c.Writer.Header().Set("Access-Control-Expose-Headers", exposeHeaders)
		}

		c.Next()
	}
}
