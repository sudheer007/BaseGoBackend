package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
)

// RedisQueue implements Queue using Redis
type RedisQueue struct {
	client         *redis.Client
	pendingQueue   string
	processingSet  string
	completedSet   string
	failedSet      string
	processingTTL  time.Duration
	completedTTL   time.Duration
	failedTTL      time.Duration
}

// RedisQueueConfig configures the Redis queue
type RedisQueueConfig struct {
	QueueName      string
	ProcessingTTL  time.Duration
	CompletedTTL   time.Duration
	FailedTTL      time.Duration
}

// DefaultRedisQueueConfig returns the default Redis queue configuration
func DefaultRedisQueueConfig() *RedisQueueConfig {
	return &RedisQueueConfig{
		QueueName:      "default",
		ProcessingTTL:  30 * time.Minute,
		CompletedTTL:   7 * 24 * time.Hour,    // Keep completed jobs for 7 days
		FailedTTL:      30 * 24 * time.Hour,   // Keep failed jobs for 30 days
	}
}

// NewRedisQueue creates a new Redis queue
func NewRedisQueue(client *redis.Client, config *RedisQueueConfig) *RedisQueue {
	if config == nil {
		config = DefaultRedisQueueConfig()
	}

	return &RedisQueue{
		client:         client,
		pendingQueue:   fmt.Sprintf("jobs:%s:pending", config.QueueName),
		processingSet:  fmt.Sprintf("jobs:%s:processing", config.QueueName),
		completedSet:   fmt.Sprintf("jobs:%s:completed", config.QueueName),
		failedSet:      fmt.Sprintf("jobs:%s:failed", config.QueueName),
		processingTTL:  config.ProcessingTTL,
		completedTTL:   config.CompletedTTL,
		failedTTL:      config.FailedTTL,
	}
}

// Enqueue adds a job to the queue
func (q *RedisQueue) Enqueue(ctx context.Context, job *Job) error {
	if job.ID == "" {
		job.ID = uuid.New().String()
	}
	
	if job.CreatedAt.IsZero() {
		job.CreatedAt = time.Now()
	}
	
	if job.RunAt.IsZero() {
		job.RunAt = job.CreatedAt
	}

	data, err := json.Marshal(job)
	if err != nil {
		return fmt.Errorf("failed to marshal job: %w", err)
	}

	// Use ZADD to add to queue with score based on runAt time
	score := float64(job.RunAt.Unix())
	_, err = q.client.ZAdd(ctx, q.pendingQueue, &redis.Z{
		Score:  score,
		Member: data,
	}).Result()
	
	return err
}

// EnqueueBatch adds multiple jobs to the queue in a single operation
func (q *RedisQueue) EnqueueBatch(ctx context.Context, jobs []*Job) error {
	if len(jobs) == 0 {
		return nil
	}

	// Create a slice of Z items for the ZADD command
	zItems := make([]*redis.Z, 0, len(jobs))
	
	for _, job := range jobs {
		if job.ID == "" {
			job.ID = uuid.New().String()
		}
		
		if job.CreatedAt.IsZero() {
			job.CreatedAt = time.Now()
		}
		
		if job.RunAt.IsZero() {
			job.RunAt = job.CreatedAt
		}

		data, err := json.Marshal(job)
		if err != nil {
			return fmt.Errorf("failed to marshal job: %w", err)
		}

		zItems = append(zItems, &redis.Z{
			Score:  float64(job.RunAt.Unix()),
			Member: data,
		})
	}

	// Add all jobs in a single ZADD command
	_, err := q.client.ZAdd(ctx, q.pendingQueue, zItems...).Result()
	return err
}

// Dequeue gets the next job from the queue
func (q *RedisQueue) Dequeue(ctx context.Context) (*Job, error) {
	now := time.Now().Unix()
	
	// Get jobs with score less than or equal to current time
	results, err := q.client.ZRangeByScore(ctx, q.pendingQueue, &redis.ZRangeBy{
		Min:    "0",
		Max:    fmt.Sprintf("%d", now),
		Offset: 0,
		Count:  1,
	}).Result()
	
	if err != nil {
		return nil, err
	}
	
	if len(results) == 0 {
		return nil, ErrNoJobAvailable
	}
	
	// Get the first job
	jobData := results[0]
	
	// Parse the job
	var job Job
	if err := json.Unmarshal([]byte(jobData), &job); err != nil {
		return nil, fmt.Errorf("failed to unmarshal job: %w", err)
	}
	
	// Increment attempt counter
	job.Attempts++
	
	// Update the job data with incremented attempts
	updatedJobData, err := json.Marshal(job)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal updated job: %w", err)
	}
	
	// Remove from pending queue and add to processing set
	pipe := q.client.Pipeline()
	pipe.ZRem(ctx, q.pendingQueue, jobData)
	pipe.Set(ctx, fmt.Sprintf("%s:%s", q.processingSet, job.ID), updatedJobData, q.processingTTL)
	_, err = pipe.Exec(ctx)
	
	if err != nil {
		return nil, err
	}
	
	return &job, nil
}

// Complete marks a job as completed
func (q *RedisQueue) Complete(ctx context.Context, job *Job) error {
	// Serialize the job
	jobData, err := json.Marshal(job)
	if err != nil {
		return fmt.Errorf("failed to marshal job: %w", err)
	}
	
	// Remove from processing and add to completed
	pipe := q.client.Pipeline()
	pipe.Del(ctx, fmt.Sprintf("%s:%s", q.processingSet, job.ID))
	pipe.Set(ctx, fmt.Sprintf("%s:%s", q.completedSet, job.ID), jobData, q.completedTTL)
	_, err = pipe.Exec(ctx)
	
	return err
}

// Failed marks a job as failed
func (q *RedisQueue) Failed(ctx context.Context, job *Job, err error) error {
	// Add error info to job
	errorInfo := map[string]string{
		"error":     err.Error(),
		"timestamp": time.Now().Format(time.RFC3339),
	}
	
	errorInfoJSON, e := json.Marshal(errorInfo)
	if e != nil {
		return fmt.Errorf("failed to marshal error info: %w", e)
	}
	
	// Add error info to job
	job.Payload = errorInfoJSON
	
	// Serialize the job
	jobData, e := json.Marshal(job)
	if e != nil {
		return fmt.Errorf("failed to marshal job: %w", e)
	}
	
	// Remove from processing and add to failed
	pipe := q.client.Pipeline()
	pipe.Del(ctx, fmt.Sprintf("%s:%s", q.processingSet, job.ID))
	pipe.Set(ctx, fmt.Sprintf("%s:%s", q.failedSet, job.ID), jobData, q.failedTTL)
	_, e = pipe.Exec(ctx)
	
	return e
}

// Retry moves a job back to the queue for retry
func (q *RedisQueue) Retry(ctx context.Context, job *Job, err error) error {
	// Calculate backoff time for retries
	backoff := calculateBackoff(job.Attempts)
	job.RunAt = time.Now().Add(backoff)
	
	// Serialize the job
	jobData, e := json.Marshal(job)
	if e != nil {
		return fmt.Errorf("failed to marshal job: %w", e)
	}
	
	// Remove from processing and add back to pending
	pipe := q.client.Pipeline()
	pipe.Del(ctx, fmt.Sprintf("%s:%s", q.processingSet, job.ID))
	pipe.ZAdd(ctx, q.pendingQueue, &redis.Z{
		Score:  float64(job.RunAt.Unix()),
		Member: jobData,
	})
	_, e = pipe.Exec(ctx)
	
	return e
}

// Size returns the current size of the queue
func (q *RedisQueue) Size(ctx context.Context) (int, error) {
	count, err := q.client.ZCard(ctx, q.pendingQueue).Result()
	return int(count), err
}

// Helper function to calculate exponential backoff for retries
func calculateBackoff(attempts int) time.Duration {
	// Simple exponential backoff: 5s, 25s, 125s, ...
	seconds := 5 * (1 << uint(attempts-1))
	
	// Cap at 1 hour
	if seconds > 3600 {
		seconds = 3600
	}
	
	return time.Duration(seconds) * time.Second
} 