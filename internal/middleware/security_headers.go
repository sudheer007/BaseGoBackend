package middleware

import (
	"fmt"

	"github.com/gin-gonic/gin"
)

// SecurityHeadersConfig defines configuration for security headers
type SecurityHeadersConfig struct {
	// ContentSecurityPolicy (CSP) header value
	ContentSecurityPolicy string

	// StrictTransportSecurity (HSTS) header value
	StrictTransportSecurity string

	// XContentTypeOptions header value
	XContentTypeOptions string

	// XFrameOptions header value
	XFrameOptions string

	// XXSSProtection header value
	XXSSProtection string

	// ReferrerPolicy header value
	ReferrerPolicy string

	// PermissionsPolicy header value
	PermissionsPolicy string
}

// DefaultSecurityHeadersConfig returns a default, reasonably secure configuration
func DefaultSecurityHeadersConfig() *SecurityHeadersConfig {
	return &SecurityHeadersConfig{
		ContentSecurityPolicy:   "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self';", // Restrictive default
		StrictTransportSecurity: "max-age=31536000; includeSubDomains; preload",                                    // Enforce HTTPS for 1 year
		XContentTypeOptions:     "nosniff",                                                                         // Prevent MIME-sniffing
		XFrameOptions:           "DENY",                                                                            // Prevent clickjacking
		XXSSProtection:          "1; mode=block",                                                                   // Enable browser XSS filter
		ReferrerPolicy:          "strict-origin-when-cross-origin",                                                 // Control referrer information
		PermissionsPolicy:       "camera=(), microphone=(), geolocation=()",                                        // Disable sensitive APIs by default
	}
}

// ApplySecurityHeaders creates a middleware that adds various security-related HTTP headers
// using the default configuration.
func ApplySecurityHeaders() gin.HandlerFunc {
	return ApplySecurityHeadersWithConfig(DefaultSecurityHeadersConfig())
}

// ApplySecurityHeadersWithConfig creates a middleware that adds various security-related HTTP headers
// using the provided configuration.
func ApplySecurityHeadersWithConfig(config *SecurityHeadersConfig) gin.HandlerFunc {
	if config == nil {
		config = DefaultSecurityHeadersConfig()
	}

	return func(c *gin.Context) {
		headers := c.Writer.Header()

		if config.ContentSecurityPolicy != "" {
			headers.Set("Content-Security-Policy", config.ContentSecurityPolicy)
		}
		if config.StrictTransportSecurity != "" {
			headers.Set("Strict-Transport-Security", config.StrictTransportSecurity)
		}
		if config.XContentTypeOptions != "" {
			headers.Set("X-Content-Type-Options", config.XContentTypeOptions)
		}
		if config.XFrameOptions != "" {
			headers.Set("X-Frame-Options", config.XFrameOptions)
		}
		if config.XXSSProtection != "" {
			headers.Set("X-XSS-Protection", config.XXSSProtection)
		}
		if config.ReferrerPolicy != "" {
			headers.Set("Referrer-Policy", config.ReferrerPolicy)
		}
		if config.PermissionsPolicy != "" {
			headers.Set("Permissions-Policy", config.PermissionsPolicy)
		}

		// Add a header to indicate middleware ran (optional, for debugging)
		headers.Set("X-Security-Middleware", "active")

		c.Next()
	}
}

// Helper to format HSTS header value
func FormatHSTS(maxAgeSeconds int, includeSubDomains bool, preload bool) string {
	value := fmt.Sprintf("max-age=%d", maxAgeSeconds)
	if includeSubDomains {
		value += "; includeSubDomains"
	}
	if preload {
		value += "; preload"
	}
	return value
}
