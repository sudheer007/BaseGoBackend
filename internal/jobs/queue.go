package jobs

import (
	"context"
	"errors"
)

// Common queue errors
var (
	ErrNoJobAvailable = errors.New("no job available")
	ErrQueueFull      = errors.New("queue is full")
	ErrInvalidJob     = errors.New("invalid job")
)

// Queue defines the interface for a job queue
type Queue interface {
	// Enqueue adds a job to the queue
	Enqueue(ctx context.Context, job *Job) error

	// EnqueueBatch adds multiple jobs to the queue in a single operation
	EnqueueBatch(ctx context.Context, jobs []*Job) error

	// Dequeue gets the next job from the queue
	Dequeue(ctx context.Context) (*Job, error)

	// Complete marks a job as completed
	Complete(ctx context.Context, job *Job) error

	// Failed marks a job as failed
	Failed(ctx context.Context, job *Job, err error) error

	// Retry moves a job back to the queue for retry
	Retry(ctx context.Context, job *Job, err error) error

	// Size returns the current size of the queue
	Size(ctx context.Context) (int, error)
}
