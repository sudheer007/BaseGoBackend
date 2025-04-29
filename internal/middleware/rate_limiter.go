package middleware

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"golang.org/x/time/rate"
)

// RateLimiterConfig holds configuration for rate limiting
type RateLimiterConfig struct {
	RPS         float64 // Requests per second
	Burst       int     // Maximum burst size
	ExpireIn    int     // Minutes until key expires
	RedisClient *redis.Client
}

// RateLimiterMiddleware implements rate limiting using Redis
type RateLimiterMiddleware struct {
	config *RateLimiterConfig
}

// NewRateLimiterMiddleware creates a new rate limiter middleware
func NewRateLimiterMiddleware(config *RateLimiterConfig) *RateLimiterMiddleware {
	return &RateLimiterMiddleware{
		config: config,
	}
}

// Limit returns the Gin middleware handler
func (m *RateLimiterMiddleware) Limit() gin.HandlerFunc {
	limiter := rate.NewLimiter(rate.Limit(m.config.RPS), m.config.Burst)

	return func(c *gin.Context) {
		// Get client IP
		clientIP := c.ClientIP()
		key := fmt.Sprintf("rate_limit:%s", clientIP)

		// Check if client is rate limited
		ctx := context.Background()
		if m.config.RedisClient != nil {
			// Use Redis-based rate limiting
			val, err := m.config.RedisClient.Get(ctx, key).Int64()
			if err == redis.Nil {
				// Key doesn't exist, set initial value
				err = m.config.RedisClient.Set(ctx, key, 1, time.Duration(m.config.ExpireIn)*time.Minute).Err()
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Rate limit error"})
					c.Abort()
					return
				}
			} else if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Rate limit error"})
				c.Abort()
				return
			} else {
				// Increment counter
				val, err = m.config.RedisClient.Incr(ctx, key).Result()
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Rate limit error"})
					c.Abort()
					return
				}

				// Check if limit exceeded
				if val > int64(m.config.Burst) {
					c.JSON(http.StatusTooManyRequests, gin.H{"error": "Rate limit exceeded"})
					c.Abort()
					return
				}
			}
		} else {
			// Use in-memory rate limiting
			if !limiter.Allow() {
				c.JSON(http.StatusTooManyRequests, gin.H{"error": "Rate limit exceeded"})
				c.Abort()
				return
			}
		}

		c.Next()
	}
} 