package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
)

// JobType defines the type of job
type JobType string

const (
	// Common job types
	JobTypeEmail      JobType = "email"
	JobTypeNotify     JobType = "notify"
	JobTypeReport     JobType = "report"
	JobTypeAudit      JobType = "audit"
	JobTypePayment    JobType = "payment"
	JobTypeFileUpload JobType = "file_upload"
)

// JobPriority defines the priority of a job
type JobPriority int

const (
	PriorityLow    JobPriority = 0
	PriorityNormal JobPriority = 1
	PriorityHigh   JobPriority = 2
)

// Job represents a background job
type Job struct {
	ID        string          `json:"id"`
	Type      JobType         `json:"type"`
	Priority  JobPriority     `json:"priority"`
	Payload   json.RawMessage `json:"payload"`
	CreatedAt time.Time       `json:"created_at"`
	RunAt     time.Time       `json:"run_at"`
	Attempts  int             `json:"attempts"`
	MaxRetry  int             `json:"max_retry"`
}

// Handler is a function that processes a job
type Handler func(context.Context, *Job) error

// WorkerConfig configures the worker
type WorkerConfig struct {
	ConcurrentWorkers int
	PollInterval      time.Duration
	QueueName         string
}

// DefaultWorkerConfig returns a default worker configuration
func DefaultWorkerConfig() *WorkerConfig {
	return &WorkerConfig{
		ConcurrentWorkers: 5,
		PollInterval:      5 * time.Second,
		QueueName:         "default",
	}
}

// Worker processes background jobs
type Worker struct {
	config      *WorkerConfig
	queue       Queue
	handlers    map[JobType]Handler
	handlersRWM sync.RWMutex
	shutdown    chan struct{}
	isRunning   bool
	wg          sync.WaitGroup
}

// New creates a new background job worker
func New(queue Queue, config *WorkerConfig) *Worker {
	if config == nil {
		config = DefaultWorkerConfig()
	}

	return &Worker{
		config:   config,
		queue:    queue,
		handlers: make(map[JobType]Handler),
		shutdown: make(chan struct{}),
	}
}

// Register registers a handler for a job type
func (w *Worker) Register(jobType JobType, handler Handler) error {
	w.handlersRWM.Lock()
	defer w.handlersRWM.Unlock()

	if _, exists := w.handlers[jobType]; exists {
		return fmt.Errorf("handler for job type %s already registered", jobType)
	}

	w.handlers[jobType] = handler
	return nil
}

// Start starts the worker pool
func (w *Worker) Start(ctx context.Context) error {
	if w.isRunning {
		return errors.New("worker already running")
	}

	w.isRunning = true
	log.Printf("Starting %d workers for queue: %s", w.config.ConcurrentWorkers, w.config.QueueName)

	for i := 0; i < w.config.ConcurrentWorkers; i++ {
		w.wg.Add(1)
		go w.process(ctx, i)
	}

	return nil
}

// Stop stops the worker pool
func (w *Worker) Stop() {
	if !w.isRunning {
		return
	}

	log.Printf("Stopping workers for queue: %s", w.config.QueueName)
	close(w.shutdown)
	w.wg.Wait()
	w.isRunning = false
	log.Printf("Workers stopped for queue: %s", w.config.QueueName)
}

// process is the main worker loop
func (w *Worker) process(ctx context.Context, workerID int) {
	defer w.wg.Done()
	log.Printf("Worker %d started for queue: %s", workerID, w.config.QueueName)

	ticker := time.NewTicker(w.config.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-w.shutdown:
			log.Printf("Worker %d shutting down for queue: %s", workerID, w.config.QueueName)
			return
		case <-ctx.Done():
			log.Printf("Worker %d context canceled for queue: %s", workerID, w.config.QueueName)
			return
		case <-ticker.C:
			if err := w.processNextJob(ctx); err != nil {
				// Only log if it's not a "no job available" error
				if !errors.Is(err, ErrNoJobAvailable) {
					log.Printf("Worker %d error processing job: %v", workerID, err)
				}
			}
		}
	}
}

// processNextJob processes the next job in the queue
func (w *Worker) processNextJob(ctx context.Context) error {
	// Fetch a job from the queue
	job, err := w.queue.Dequeue(ctx)
	if err != nil {
		return err
	}

	// Get the handler for this job type
	w.handlersRWM.RLock()
	handler, exists := w.handlers[job.Type]
	w.handlersRWM.RUnlock()

	if !exists {
		log.Printf("No handler registered for job type: %s", job.Type)
		// Move to a dead letter queue or handle unprocessable jobs
		return w.queue.Failed(ctx, job, fmt.Errorf("no handler for job type: %s", job.Type))
	}

	// Process the job
	err = handler(ctx, job)
	if err != nil {
		log.Printf("Error processing job %s (type: %s): %v", job.ID, job.Type, err)

		// If we should retry
		if job.Attempts < job.MaxRetry {
			return w.queue.Retry(ctx, job, err)
		}

		// Otherwise mark as failed
		return w.queue.Failed(ctx, job, err)
	}

	// Mark the job as completed
	return w.queue.Complete(ctx, job)
}
