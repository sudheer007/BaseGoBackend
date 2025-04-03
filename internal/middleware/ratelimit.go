package middleware

import (
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"

	"gobackend/internal/security"
)

// RateLimiterType defines the type of rate limiter
type RateLimiterType int

const (
	// LimiterTypeIP limits requests based on client IP
	LimiterTypeIP RateLimiterType = iota

	// LimiterTypeUser limits requests based on user ID
	LimiterTypeUser

	// LimiterTypeTenant limits requests based on tenant ID
	LimiterTypeTenant

	// LimiterTypeEndpoint limits requests based on endpoint path
	LimiterTypeEndpoint

	// LimiterTypeGlobal applies global rate limiting
	LimiterTypeGlobal
)

// RateLimitStrategy defines how rate limiting is enforced
type RateLimitStrategy int

const (
	// StrategyToken uses token bucket algorithm
	StrategyToken RateLimitStrategy = iota

	// StrategyFixedWindow uses fixed window counting
	StrategyFixedWindow

	// StrategySlidingWindow uses sliding window counting
	StrategySlidingWindow

	// StrategyAdaptive uses adaptive rate limiting based on server load
	StrategyAdaptive
)

// RateLimitConfig defines rate limiting configuration
type RateLimitConfig struct {
	// Enabled determines if rate limiting is active
	Enabled bool

	// Strategy defines the rate limiting algorithm
	Strategy RateLimitStrategy

	// Types defines which limiters to use
	Types []RateLimiterType

	// GlobalLimit defines requests per second for all traffic
	GlobalLimit rate.Limit

	// IPLimit defines requests per second per IP
	IPLimit rate.Limit

	// UserLimit defines requests per second per user
	UserLimit rate.Limit

	// TenantLimit defines requests per second per tenant
	TenantLimit rate.Limit

	// EndpointLimits defines paths with custom limits
	EndpointLimits map[string]rate.Limit

	// Burst defines how many tokens can be consumed in a burst
	Burst int

	// ExcludedPaths defines paths to exclude from rate limiting
	ExcludedPaths []string

	// ExcludedIPs defines IPs to exclude from rate limiting
	ExcludedIPs []string

	// StatusCode defines the HTTP status code for rate limit errors
	StatusCode int

	// ErrorMessage defines the error message for rate limit errors
	ErrorMessage string

	// Headers determines if rate limit headers should be included
	Headers bool
}

// DefaultRateLimitConfig returns default rate limit configuration
func DefaultRateLimitConfig() *RateLimitConfig {
	return &RateLimitConfig{
		Enabled:      true,
		Strategy:     StrategyToken,
		Types:        []RateLimiterType{LimiterTypeIP},
		GlobalLimit:  rate.Limit(100),
		IPLimit:      rate.Limit(10),
		UserLimit:    rate.Limit(20),
		TenantLimit:  rate.Limit(50),
		Burst:        5,
		StatusCode:   http.StatusTooManyRequests,
		ErrorMessage: security.ErrMsgRateLimitExceeded,
		Headers:      true,
	}
}

// StrictRateLimitConfig returns a more restrictive rate limit configuration
func StrictRateLimitConfig() *RateLimitConfig {
	return &RateLimitConfig{
		Enabled:      true,
		Strategy:     StrategyToken,
		Types:        []RateLimiterType{LimiterTypeIP, LimiterTypeUser, LimiterTypeTenant, LimiterTypeEndpoint},
		GlobalLimit:  rate.Limit(50),
		IPLimit:      rate.Limit(5),
		UserLimit:    rate.Limit(10),
		TenantLimit:  rate.Limit(30),
		Burst:        3,
		StatusCode:   http.StatusTooManyRequests,
		ErrorMessage: security.ErrMsgRateLimitExceeded,
		Headers:      true,
	}
}

// limiterVisitor holds a rate limiter for a specific key
type limiterVisitor struct {
	limiter      *rate.Limiter
	lastSeen     time.Time
	totalHits    int64
	rejectedHits int64
}

// rateLimitStore manages rate limiters with cleanup
type rateLimitStore struct {
	visitors map[string]*limiterVisitor
	mu       sync.RWMutex
	done     chan struct{}
}

// newRateLimitStore creates a new store with cleanup goroutine
func newRateLimitStore() *rateLimitStore {
	store := &rateLimitStore{
		visitors: make(map[string]*limiterVisitor),
		done:     make(chan struct{}),
	}

	// Start cleanup goroutine
	go store.cleanup()

	return store
}

// Close shuts down the cleanup goroutine
func (s *rateLimitStore) Close() {
	close(s.done)
}

// cleanup periodically removes old limiters
func (s *rateLimitStore) cleanup() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.mu.Lock()
			for k, v := range s.visitors {
				if time.Since(v.lastSeen) > 24*time.Hour {
					delete(s.visitors, k)
				}
			}
			s.mu.Unlock()
		case <-s.done:
			return
		}
	}
}

// getVisitor gets or creates a limiter for the given key
func (s *rateLimitStore) getVisitor(key string, l rate.Limit, burst int) *limiterVisitor {
	s.mu.RLock()
	v, exists := s.visitors[key]
	s.mu.RUnlock()

	if !exists {
		limiter := rate.NewLimiter(l, burst)
		v = &limiterVisitor{
			limiter:  limiter,
			lastSeen: time.Now(),
		}

		s.mu.Lock()
		s.visitors[key] = v
		s.mu.Unlock()
	}

	v.lastSeen = time.Now()
	return v
}

// allow checks if a request is allowed
func (s *rateLimitStore) allow(key string, l rate.Limit, burst int) bool {
	v := s.getVisitor(key, l, burst)
	v.totalHits++

	allowed := v.limiter.Allow()
	if !allowed {
		v.rejectedHits++
	}

	return allowed
}

// RateLimitDefault middleware implements rate limiting with default config
func RateLimitDefault() gin.HandlerFunc {
	return RateLimitWithConfig(DefaultRateLimitConfig())
}

// RateLimitWithConfig middleware implements rate limiting with custom config
func RateLimitWithConfig(config *RateLimitConfig) gin.HandlerFunc {
	if config == nil {
		config = DefaultRateLimitConfig()
	}

	if !config.Enabled {
		return func(c *gin.Context) {
			c.Next()
		}
	}

	// Create stores for each limiter type
	var ipStore, userStore, tenantStore, endpointStore, globalStore *rateLimitStore

	for _, t := range config.Types {
		switch t {
		case LimiterTypeIP:
			ipStore = newRateLimitStore()
		case LimiterTypeUser:
			userStore = newRateLimitStore()
		case LimiterTypeTenant:
			tenantStore = newRateLimitStore()
		case LimiterTypeEndpoint:
			endpointStore = newRateLimitStore()
		case LimiterTypeGlobal:
			globalStore = newRateLimitStore()
		}
	}

	// Return middleware function
	return func(c *gin.Context) {
		// Check if path is excluded
		for _, path := range config.ExcludedPaths {
			if c.Request.URL.Path == path {
				c.Next()
				return
			}
		}

		// Get client IP
		clientIP := c.ClientIP()

		// Check if IP is excluded
		for _, ip := range config.ExcludedIPs {
			if clientIP == ip {
				c.Next()
				return
			}
		}

		// Get identifiers for limiters
		userID := getUserID(c)
		tenantID := getTenantID(c)
		endpoint := c.Request.URL.Path

		// Check each active limiter
		for _, t := range config.Types {
			var exceeded bool

			switch t {
			case LimiterTypeIP:
				if ipStore != nil && !ipStore.allow(clientIP, config.IPLimit, config.Burst) {
					exceeded = true
				}
			case LimiterTypeUser:
				if userStore != nil && userID != "" && !userStore.allow(userID, config.UserLimit, config.Burst) {
					exceeded = true
				}
			case LimiterTypeTenant:
				if tenantStore != nil && tenantID != "" && !tenantStore.allow(tenantID, config.TenantLimit, config.Burst) {
					exceeded = true
				}
			case LimiterTypeEndpoint:
				if endpointStore != nil {
					// Check for custom endpoint limit
					limit := config.IPLimit // Default to IP limit
					if custom, exists := config.EndpointLimits[endpoint]; exists {
						limit = custom
					}
					if !endpointStore.allow(endpoint, limit, config.Burst) {
						exceeded = true
					}
				}
			case LimiterTypeGlobal:
				if globalStore != nil && !globalStore.allow("global", config.GlobalLimit, config.Burst) {
					exceeded = true
				}
			}

			if exceeded {
				// Add rate limit headers if enabled
				if config.Headers {
					// Common rate limit headers
					c.Header("X-RateLimit-Limit", strconv.Itoa(config.Burst))
					c.Header("X-RateLimit-Remaining", "0")
					c.Header("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(time.Second).Unix(), 10))
					c.Header("Retry-After", "1")
				}

				// Return rate limit error
				c.AbortWithStatusJSON(config.StatusCode, gin.H{
					"error":   "rate_limit_exceeded",
					"message": config.ErrorMessage,
				})
				return
			}
		}

		// Add remaining rate limit headers if enabled
		if config.Headers {
			c.Header("X-RateLimit-Limit", strconv.Itoa(config.Burst))
			// We could calculate the exact remaining tokens, but that would require more complex logic
			c.Header("X-RateLimit-Remaining", strconv.Itoa(1)) // Simplified
		}

		c.Next()
	}
}

// Helper functions

// getUserID extracts user ID from context
func getUserID(c *gin.Context) string {
	// Try to get from context
	if userID, exists := c.Get(string(security.ContextKeyUserID)); exists {
		if id, ok := userID.(string); ok {
			return id
		}
	}

	// Try to get from request headers
	if userID := c.GetHeader("X-User-ID"); userID != "" {
		return userID
	}

	return ""
}

// getTenantID extracts tenant ID from context
func getTenantID(c *gin.Context) string {
	// Try to get from context
	if tenantID, exists := c.Get(string(security.ContextKeyTenantID)); exists {
		if id, ok := tenantID.(string); ok {
			return id
		}
	}

	// Try to get from request headers
	if tenantID := c.GetHeader("X-Tenant-ID"); tenantID != "" {
		return tenantID
	}

	return ""
}

// IsPrivateIP checks if an IP is private
func IsPrivateIP(ip string) bool {
	// Parse IP address
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// Check against private IP ranges
	privateIPBlocks := []*net.IPNet{
		mustParseCIDR(security.PrivateNetworkCIDR_10),
		mustParseCIDR(security.PrivateNetworkCIDR_172),
		mustParseCIDR(security.PrivateNetworkCIDR_192),
		mustParseCIDR(security.PrivateNetworkCIDR_Local),
	}

	for _, block := range privateIPBlocks {
		if block.Contains(parsedIP) {
			return true
		}
	}

	return false
}

// mustParseCIDR parses CIDR notation or panics
func mustParseCIDR(cidr string) *net.IPNet {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	return ipNet
}
