package middleware

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// Security headers
const (
	XFrameOptions           = "DENY"
	XContentTypeOptions     = "nosniff"
	XXSSProtection          = "1; mode=block"
	ContentSecurityPolicy   = "default-src 'self'; script-src 'self'; object-src 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self'; frame-src 'none'; connect-src 'self'"
	StrictTransportSecurity = "max-age=31536000; includeSubDomains; preload"
	ReferrerPolicy          = "strict-origin-when-cross-origin"
	PermissionsPolicy       = "camera=(), microphone=(), geolocation=()"
	CacheControl            = "no-store, no-cache, must-revalidate, max-age=0"
	Pragma                  = "no-cache"
)

// ClientIP gets the real client IP, taking into account proxies
func ClientIP(c *gin.Context) string {
	// Try to get IP from X-Forwarded-For header
	forwardedFor := c.GetHeader("X-Forwarded-For")
	if forwardedFor != "" {
		// The client IP is the first one in the list
		ips := strings.Split(forwardedFor, ",")
		if len(ips) > 0 {
			clientIP := strings.TrimSpace(ips[0])
			if clientIP != "" {
				return clientIP
			}
		}
	}

	// Try to get IP from X-Real-IP header
	realIP := c.GetHeader("X-Real-IP")
	if realIP != "" {
		return realIP
	}

	// Fallback to the remote address
	return c.ClientIP()
}

// SecurityHeaders adds security headers to responses
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Frame-Options", XFrameOptions)
		c.Header("X-Content-Type-Options", XContentTypeOptions)
		c.Header("X-XSS-Protection", XXSSProtection)
		c.Header("Content-Security-Policy", ContentSecurityPolicy)
		c.Header("Strict-Transport-Security", StrictTransportSecurity)
		c.Header("Referrer-Policy", ReferrerPolicy)
		c.Header("Permissions-Policy", PermissionsPolicy)
		c.Header("Cache-Control", CacheControl)
		c.Header("Pragma", Pragma)

		// Remove potentially sensitive headers
		c.Header("Server", "")
		c.Header("X-Powered-By", "")

		c.Next()
	}
}

// RateLimit applies rate limiting to API endpoints
type RateLimit struct {
	limiters map[string]*rate.Limiter
}

// NewRateLimit creates a new rate limiter
func NewRateLimit() *RateLimit {
	return &RateLimit{
		limiters: make(map[string]*rate.Limiter),
	}
}

// Limit applies rate limiting middleware
func (r *RateLimit) Limit(rps float64, burst int) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get client IP
		ip := ClientIP(c)

		// Get or create limiter for this IP
		var limiter *rate.Limiter
		if l, exists := r.limiters[ip]; exists {
			limiter = l
		} else {
			limiter = rate.NewLimiter(rate.Limit(rps), burst)
			r.limiters[ip] = limiter
		}

		// Check if rate limit is exceeded
		if !limiter.Allow() {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "Rate limit exceeded",
			})
			return
		}

		c.Next()
	}
}

// CORS configures CORS headers
func CORS(allowedOrigins string) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")

		// Set CORS headers based on allowed origins
		if allowedOrigins == "*" {
			c.Header("Access-Control-Allow-Origin", origin)
		} else if strings.Contains(allowedOrigins, origin) {
			c.Header("Access-Control-Allow-Origin", origin)
		}

		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Max-Age", "86400") // 24 hours

		// Handle preflight requests
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// RequestLogger logs request details
func RequestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Start timer
		start := time.Now()

		// Process request
		c.Next()

		// Log request details
		latency := time.Since(start)
		clientIP := ClientIP(c)
		method := c.Request.Method
		path := c.Request.URL.Path
		statusCode := c.Writer.Status()

		// Log the request (this can be replaced with a structured logger)
		// Use appropriate log levels based on status code
		if statusCode >= 500 {
			// Error level for server errors
			log := gin.DefaultErrorWriter
			fmt.Fprintf(log, "[ERROR] %s | %3d | %13v | %s | %s\n",
				clientIP, statusCode, latency, method, path)
		} else if statusCode >= 400 {
			// Warning level for client errors
			log := gin.DefaultErrorWriter
			fmt.Fprintf(log, "[WARN] %s | %3d | %13v | %s | %s\n",
				clientIP, statusCode, latency, method, path)
		} else {
			// Info level for successful requests
			log := gin.DefaultWriter
			fmt.Fprintf(log, "[INFO] %s | %3d | %13v | %s | %s\n",
				clientIP, statusCode, latency, method, path)
		}
	}
}

// Recovery handles panics and returns a 500 error
func Recovery() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				// Log the error
				log := gin.DefaultErrorWriter
				fmt.Fprintf(log, "[FATAL] Panic recovered: %v\n", err)

				// Return a 500 error
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": "Internal server error",
				})
			}
		}()

		c.Next()
	}
}
