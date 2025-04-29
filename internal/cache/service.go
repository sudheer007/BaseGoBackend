package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
)

// Config holds Redis connection configuration
type Config struct {
	Host     string
	Port     int
	Password string
	DB       int
	Enabled  bool
}

// Service provides caching functionality
type Service struct {
	client  *redis.Client
	enabled bool
}

// NewService creates a new cache service
func NewService(cfg *Config) (*Service, error) {
	if cfg == nil {
		return nil, errors.New("cache config cannot be nil")
	}

	if !cfg.Enabled {
		return &Service{enabled: false}, nil
	}

	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Password: cfg.Password,
		DB:       cfg.DB,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &Service{
		client:  client,
		enabled: true,
	}, nil
}

// Get retrieves a value from cache, unmarshaling it into the provided destination
func (s *Service) Get(ctx context.Context, key string, dest interface{}) error {
	if !s.enabled {
		return errors.New("cache is disabled")
	}

	val, err := s.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return errors.New("key not found")
		}
		return err
	}

	return json.Unmarshal([]byte(val), dest)
}

// Set stores a value in cache with an expiration time
func (s *Service) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	if !s.enabled {
		return errors.New("cache is disabled")
	}

	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal value: %w", err)
	}

	return s.client.Set(ctx, key, data, expiration).Err()
}

// Delete removes a key from cache
func (s *Service) Delete(ctx context.Context, key string) error {
	if !s.enabled {
		return errors.New("cache is disabled")
	}

	return s.client.Del(ctx, key).Err()
}

// Close closes the Redis connection
func (s *Service) Close() error {
	if !s.enabled || s.client == nil {
		return nil
	}
	return s.client.Close()
} 