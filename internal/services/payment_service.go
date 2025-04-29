package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"gobackend/internal/audit"
	"gobackend/internal/jobs"
	"gobackend/razorpay"
	"log"
	"time"

	"github.com/google/uuid"
)

// PaymentProvider represents the type of payment provider
type PaymentProvider string

const (
	ProviderRazorpay PaymentProvider = "razorpay"
	// Add more providers as needed
)

// PaymentStatus represents the status of a payment
type PaymentStatus string

const (
	PaymentStatusPending   PaymentStatus = "pending"
	PaymentStatusCompleted PaymentStatus = "completed"
	PaymentStatusFailed    PaymentStatus = "failed"
	PaymentStatusRefunded  PaymentStatus = "refunded"
	PaymentStatusCancelled PaymentStatus = "cancelled"
)

// SubscriptionStatus represents the status of a subscription
type SubscriptionStatus string

const (
	SubscriptionStatusActive    SubscriptionStatus = "active"
	SubscriptionStatusCancelled SubscriptionStatus = "cancelled"
	SubscriptionStatusPaused    SubscriptionStatus = "paused"
	SubscriptionStatusExpired   SubscriptionStatus = "expired"
	SubscriptionStatusPending   SubscriptionStatus = "pending"
)

// PaymentService handles payment operations
type PaymentService struct {
	db           *sql.DB
	auditService *audit.Service
	razorpay     *razorpay.Client
	jobQueue     jobs.Queue
}

// NewPaymentService creates a new payment service
func NewPaymentService(db *sql.DB, auditService *audit.Service, razorpayClient *razorpay.Client, jobQueue jobs.Queue) *PaymentService {
	return &PaymentService{
		db:           db,
		auditService: auditService,
		razorpay:     razorpayClient,
		jobQueue:     jobQueue,
	}
}

// PaymentRequest represents a request to process a payment
type PaymentRequest struct {
	Amount         float64         `json:"amount"`
	Currency       string          `json:"currency"`
	Description    string          `json:"description"`
	UserID         string          `json:"user_id"`
	OrganizationID string          `json:"organization_id"`
	Provider       PaymentProvider `json:"provider"`
	Metadata       json.RawMessage `json:"metadata,omitempty"`
}

// SubscriptionRequest represents a request to create a subscription
type SubscriptionRequest struct {
	PlanID         string          `json:"plan_id"`
	UserID         string          `json:"user_id"`
	OrganizationID string          `json:"organization_id"`
	Provider       PaymentProvider `json:"provider"`
	StartDate      *time.Time      `json:"start_date,omitempty"`
	BillingCycles  int             `json:"billing_cycles,omitempty"`
	Metadata       json.RawMessage `json:"metadata,omitempty"`
}

// PaymentVerificationRequest is used to verify a payment
type PaymentVerificationRequest struct {
	PaymentID      string          `json:"payment_id"`
	SubscriptionID string          `json:"subscription_id"`
	Signature      string          `json:"signature"`
	Provider       PaymentProvider `json:"provider"`
}

// PaymentResponse contains details of a payment
type PaymentResponse struct {
	PaymentID      string          `json:"payment_id"`
	ExternalID     string          `json:"external_id,omitempty"`
	Amount         float64         `json:"amount"`
	Currency       string          `json:"currency"`
	Status         PaymentStatus   `json:"status"`
	CreatedAt      time.Time       `json:"created_at"`
	CompletedAt    *time.Time      `json:"completed_at,omitempty"`
	UserID         string          `json:"user_id"`
	OrganizationID string          `json:"organization_id"`
	Provider       PaymentProvider `json:"provider"`
	Description    string          `json:"description"`
	Metadata       json.RawMessage `json:"metadata,omitempty"`
}

// SubscriptionResponse contains details of a subscription
type SubscriptionResponse struct {
	SubscriptionID string             `json:"subscription_id"`
	ExternalID     string             `json:"external_id,omitempty"`
	PlanID         string             `json:"plan_id"`
	ExternalPlanID string             `json:"external_plan_id,omitempty"`
	Status         SubscriptionStatus `json:"status"`
	StartDate      time.Time          `json:"start_date"`
	EndDate        *time.Time         `json:"end_date,omitempty"`
	UserID         string             `json:"user_id"`
	OrganizationID string             `json:"organization_id"`
	Provider       PaymentProvider    `json:"provider"`
	Metadata       json.RawMessage    `json:"metadata,omitempty"`
}

// ProcessPayment processes a payment
func (s *PaymentService) ProcessPayment(ctx context.Context, req PaymentRequest) (*PaymentResponse, error) {
	// Validate request
	if req.Amount <= 0 {
		return nil, errors.New("amount must be greater than zero")
	}

	if req.UserID == "" {
		return nil, errors.New("user ID is required")
	}

	if req.OrganizationID == "" {
		return nil, errors.New("organization ID is required")
	}

	// Generate payment ID
	paymentID := uuid.New().String()

	// Store payment in database with pending status
	status := PaymentStatusPending
	createdAt := time.Now()

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO payments (
			id, external_id, amount, currency, status, created_at, 
			user_id, organization_id, provider, description, metadata
		) VALUES (?, '', ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		paymentID, req.Amount, req.Currency, status, createdAt,
		req.UserID, req.OrganizationID, req.Provider, req.Description, req.Metadata,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create payment record: %w", err)
	}

	// Log audit event
	s.auditService.LogEvent(ctx, "payment.created", map[string]interface{}{
		"payment_id":      paymentID,
		"user_id":         req.UserID,
		"organization_id": req.OrganizationID,
		"amount":          req.Amount,
		"currency":        req.Currency,
	})

	// Return payment response
	return &PaymentResponse{
		PaymentID:      paymentID,
		Amount:         req.Amount,
		Currency:       req.Currency,
		Status:         status,
		CreatedAt:      createdAt,
		UserID:         req.UserID,
		OrganizationID: req.OrganizationID,
		Provider:       req.Provider,
		Description:    req.Description,
		Metadata:       req.Metadata,
	}, nil
}

// VerifyPayment verifies a payment
func (s *PaymentService) VerifyPayment(ctx context.Context, req PaymentVerificationRequest) error {
	if req.Provider != ProviderRazorpay {
		return fmt.Errorf("unsupported payment provider: %s", req.Provider)
	}

	// Use Razorpay client to verify the payment
	verificationReq := razorpay.VerificationRequest{
		PaymentID:      req.PaymentID,
		SubscriptionID: req.SubscriptionID,
		Signature:      req.Signature,
	}

	err := s.razorpay.VerifyPayment(verificationReq)
	if err != nil {
		return fmt.Errorf("payment verification failed: %w", err)
	}

	// Update payment status in database
	completedAt := time.Now()
	_, err = s.db.ExecContext(ctx, `
		UPDATE payments SET 
		status = ?, 
		completed_at = ?, 
		external_id = ? 
		WHERE id = ?`,
		PaymentStatusCompleted, completedAt, req.PaymentID, req.SubscriptionID,
	)

	if err != nil {
		return fmt.Errorf("failed to update payment record: %w", err)
	}

	// Log audit event
	s.auditService.LogEvent(ctx, "payment.verified", map[string]interface{}{
		"payment_id":      req.PaymentID,
		"subscription_id": req.SubscriptionID,
	})

	// Queue a job to send payment receipt
	s.queueReceiptJob(ctx, req.PaymentID)

	return nil
}

// CreateSubscription creates a new subscription
func (s *PaymentService) CreateSubscription(ctx context.Context, req SubscriptionRequest) (*SubscriptionResponse, error) {
	if req.Provider != ProviderRazorpay {
		return nil, fmt.Errorf("unsupported payment provider: %s", req.Provider)
	}

	if req.PlanID == "" {
		return nil, errors.New("plan ID is required")
	}

	if req.UserID == "" {
		return nil, errors.New("user ID is required")
	}

	if req.OrganizationID == "" {
		return nil, errors.New("organization ID is required")
	}

	// Get plan details from database
	var externalPlanID string
	var planMetadata json.RawMessage

	err := s.db.QueryRowContext(ctx, `
		SELECT external_id, metadata FROM plans WHERE id = ?`, req.PlanID,
	).Scan(&externalPlanID, &planMetadata)

	if err != nil {
		return nil, fmt.Errorf("failed to fetch plan details: %w", err)
	}

	// Create subscription in Razorpay
	subscriptionReq := razorpay.SubscriptionRequest{
		PlanID:         externalPlanID,
		CustomerNotify: true,
	}

	if req.StartDate != nil {
		subscriptionReq.StartAt = req.StartDate
	}

	if req.BillingCycles > 0 {
		subscriptionReq.TotalCount = req.BillingCycles
	}

	// Add user info to metadata
	metadata := map[string]string{
		"user_id":         req.UserID,
		"organization_id": req.OrganizationID,
	}

	// Add custom metadata if provided
	if len(req.Metadata) > 0 {
		var customMetadata map[string]string
		if err := json.Unmarshal(req.Metadata, &customMetadata); err == nil {
			for k, v := range customMetadata {
				metadata[k] = v
			}
		}
	}

	subscriptionReq.Notes = metadata

	// Create subscription in Razorpay
	result, err := s.razorpay.CreateSubscription(subscriptionReq)
	if err != nil {
		return nil, fmt.Errorf("failed to create subscription: %w", err)
	}

	// Get external subscription ID from response
	externalID, ok := result["id"].(string)
	if !ok {
		return nil, errors.New("invalid subscription ID in response")
	}

	// Generate subscription ID
	subscriptionID := uuid.New().String()
	status := SubscriptionStatusPending
	startDate := time.Now()

	// Insert subscription into database
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO subscriptions (
			id, external_id, plan_id, external_plan_id, status, start_date,
			user_id, organization_id, provider, metadata
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		subscriptionID, externalID, req.PlanID, externalPlanID, status, startDate,
		req.UserID, req.OrganizationID, req.Provider, req.Metadata,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create subscription record: %w", err)
	}

	// Log audit event
	s.auditService.LogEvent(ctx, "subscription.created", map[string]interface{}{
		"subscription_id": subscriptionID,
		"external_id":     externalID,
		"plan_id":         req.PlanID,
		"user_id":         req.UserID,
		"organization_id": req.OrganizationID,
	})

	return &SubscriptionResponse{
		SubscriptionID: subscriptionID,
		ExternalID:     externalID,
		PlanID:         req.PlanID,
		ExternalPlanID: externalPlanID,
		Status:         status,
		StartDate:      startDate,
		UserID:         req.UserID,
		OrganizationID: req.OrganizationID,
		Provider:       req.Provider,
		Metadata:       req.Metadata,
	}, nil
}

// CancelSubscription cancels an active subscription
func (s *PaymentService) CancelSubscription(ctx context.Context, subscriptionID string, cancelAtEnd bool) error {
	// Get subscription details from database
	var externalID string
	var provider PaymentProvider

	err := s.db.QueryRowContext(ctx, `
		SELECT external_id, provider FROM subscriptions WHERE id = ?`, subscriptionID,
	).Scan(&externalID, &provider)

	if err != nil {
		if err == sql.ErrNoRows {
			return errors.New("subscription not found")
		}
		return fmt.Errorf("failed to fetch subscription details: %w", err)
	}

	if provider != ProviderRazorpay {
		return fmt.Errorf("unsupported payment provider: %s", provider)
	}

	// Cancel subscription in Razorpay
	_, err = s.razorpay.CancelSubscription(externalID, cancelAtEnd)
	if err != nil {
		return fmt.Errorf("failed to cancel subscription: %w", err)
	}

	// Update subscription status in database
	status := SubscriptionStatusCancelled
	endDate := time.Now()

	_, err = s.db.ExecContext(ctx, `
		UPDATE subscriptions SET 
		status = ?, 
		end_date = ? 
		WHERE id = ?`,
		status, endDate, subscriptionID,
	)

	if err != nil {
		return fmt.Errorf("failed to update subscription record: %w", err)
	}

	// Log audit event
	s.auditService.LogEvent(ctx, "subscription.cancelled", map[string]interface{}{
		"subscription_id": subscriptionID,
		"external_id":     externalID,
		"cancel_at_end":   cancelAtEnd,
	})

	return nil
}

// GetPaymentByID retrieves payment details by ID
func (s *PaymentService) GetPaymentByID(ctx context.Context, paymentID string) (*PaymentResponse, error) {
	var payment PaymentResponse

	err := s.db.QueryRowContext(ctx, `
		SELECT 
			id, external_id, amount, currency, status, created_at, completed_at,
			user_id, organization_id, provider, description, metadata
		FROM payments 
		WHERE id = ?`, paymentID,
	).Scan(
		&payment.PaymentID, &payment.ExternalID, &payment.Amount, &payment.Currency,
		&payment.Status, &payment.CreatedAt, &payment.CompletedAt,
		&payment.UserID, &payment.OrganizationID, &payment.Provider,
		&payment.Description, &payment.Metadata,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("payment not found")
		}
		return nil, fmt.Errorf("failed to fetch payment details: %w", err)
	}

	return &payment, nil
}

// GetSubscriptionByID retrieves subscription details by ID
func (s *PaymentService) GetSubscriptionByID(ctx context.Context, subscriptionID string) (*SubscriptionResponse, error) {
	var subscription SubscriptionResponse

	err := s.db.QueryRowContext(ctx, `
		SELECT 
			id, external_id, plan_id, external_plan_id, status, start_date, end_date,
			user_id, organization_id, provider, metadata
		FROM subscriptions 
		WHERE id = ?`, subscriptionID,
	).Scan(
		&subscription.SubscriptionID, &subscription.ExternalID, &subscription.PlanID,
		&subscription.ExternalPlanID, &subscription.Status, &subscription.StartDate,
		&subscription.EndDate, &subscription.UserID, &subscription.OrganizationID,
		&subscription.Provider, &subscription.Metadata,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("subscription not found")
		}
		return nil, fmt.Errorf("failed to fetch subscription details: %w", err)
	}

	return &subscription, nil
}

// HandleWebhook processes webhook events from payment providers
func (s *PaymentService) HandleWebhook(ctx context.Context, provider PaymentProvider, payload []byte, signature string) error {
	if provider != ProviderRazorpay {
		return fmt.Errorf("unsupported payment provider: %s", provider)
	}

	// Verify webhook signature
	err := s.razorpay.VerifyWebhookSignature(payload, signature)
	if err != nil {
		return fmt.Errorf("webhook signature verification failed: %w", err)
	}

	// Parse webhook event
	var event razorpay.WebhookEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		return fmt.Errorf("failed to parse webhook event: %w", err)
	}

	// Process event based on type
	switch {
	case contains(event.Contains, "subscription"):
		return s.processSubscriptionEvent(ctx, event)
	case contains(event.Contains, "payment"):
		return s.processPaymentEvent(ctx, event)
	default:
		log.Printf("Unhandled webhook event type: %v", event.Contains)
		return nil
	}
}

// processSubscriptionEvent processes subscription-related webhook events
func (s *PaymentService) processSubscriptionEvent(ctx context.Context, event razorpay.WebhookEvent) error {
	subscription, ok := event.Payload["subscription"].(map[string]interface{})
	if !ok {
		return errors.New("invalid subscription payload")
	}

	externalID, ok := subscription["id"].(string)
	if !ok {
		return errors.New("invalid subscription ID")
	}

	// Get subscription from database
	var subscriptionID string
	err := s.db.QueryRowContext(ctx, `
		SELECT id FROM subscriptions WHERE external_id = ?`, externalID,
	).Scan(&subscriptionID)

	if err != nil {
		return fmt.Errorf("failed to fetch subscription: %w", err)
	}

	// Process based on event type
	switch event.Entity {
	case "subscription.activated":
		// Update subscription status
		_, err = s.db.ExecContext(ctx, `
			UPDATE subscriptions SET status = ? WHERE id = ?`,
			SubscriptionStatusActive, subscriptionID,
		)

		s.auditService.LogEvent(ctx, "subscription.activated", map[string]interface{}{
			"subscription_id": subscriptionID,
			"external_id":     externalID,
		})

	case "subscription.cancelled":
		// Update subscription status
		endDate := time.Now()
		_, err = s.db.ExecContext(ctx, `
			UPDATE subscriptions SET status = ?, end_date = ? WHERE id = ?`,
			SubscriptionStatusCancelled, endDate, subscriptionID,
		)

		s.auditService.LogEvent(ctx, "subscription.cancelled", map[string]interface{}{
			"subscription_id": subscriptionID,
			"external_id":     externalID,
		})

	case "subscription.pending":
		// Update subscription status
		_, err = s.db.ExecContext(ctx, `
			UPDATE subscriptions SET status = ? WHERE id = ?`,
			SubscriptionStatusPending, subscriptionID,
		)

	case "subscription.halted":
		// Update subscription status
		_, err = s.db.ExecContext(ctx, `
			UPDATE subscriptions SET status = ? WHERE id = ?`,
			SubscriptionStatusPaused, subscriptionID,
		)

		s.auditService.LogEvent(ctx, "subscription.halted", map[string]interface{}{
			"subscription_id": subscriptionID,
			"external_id":     externalID,
		})

	default:
		log.Printf("Unhandled subscription event: %s", event.Entity)
	}

	return err
}

// processPaymentEvent processes payment-related webhook events
func (s *PaymentService) processPaymentEvent(ctx context.Context, event razorpay.WebhookEvent) error {
	payment, ok := event.Payload["payment"].(map[string]interface{})
	if !ok {
		return errors.New("invalid payment payload")
	}

	externalID, ok := payment["id"].(string)
	if !ok {
		return errors.New("invalid payment ID")
	}

	// Get payment from database
	var paymentID string
	err := s.db.QueryRowContext(ctx, `
		SELECT id FROM payments WHERE external_id = ?`, externalID,
	).Scan(&paymentID)

	if err != nil {
		return fmt.Errorf("failed to fetch payment: %w", err)
	}

	// Process based on event type
	switch event.Entity {
	case "payment.authorized":
		// Update payment status
		completedAt := time.Now()
		_, err = s.db.ExecContext(ctx, `
			UPDATE payments SET status = ?, completed_at = ? WHERE id = ?`,
			PaymentStatusCompleted, completedAt, paymentID,
		)

		s.auditService.LogEvent(ctx, "payment.completed", map[string]interface{}{
			"payment_id":  paymentID,
			"external_id": externalID,
		})

		// Queue a job to send payment receipt
		s.queueReceiptJob(ctx, paymentID)

	case "payment.failed":
		// Update payment status
		_, err = s.db.ExecContext(ctx, `
			UPDATE payments SET status = ? WHERE id = ?`,
			PaymentStatusFailed, paymentID,
		)

		s.auditService.LogEvent(ctx, "payment.failed", map[string]interface{}{
			"payment_id":  paymentID,
			"external_id": externalID,
		})

	case "refund.created":
		// Update payment status
		_, err = s.db.ExecContext(ctx, `
			UPDATE payments SET status = ? WHERE id = ?`,
			PaymentStatusRefunded, paymentID,
		)

		s.auditService.LogEvent(ctx, "payment.refunded", map[string]interface{}{
			"payment_id":  paymentID,
			"external_id": externalID,
		})

	default:
		log.Printf("Unhandled payment event: %s", event.Entity)
	}

	return err
}

// queueReceiptJob queues a job to send a payment receipt
func (s *PaymentService) queueReceiptJob(ctx context.Context, paymentID string) error {
	if s.jobQueue == nil {
		log.Println("Job queue not configured, skipping receipt job")
		return nil
	}

	// Create a job to send the receipt
	job := &jobs.Job{
		Type:     jobs.JobTypeEmail,
		Priority: jobs.PriorityNormal,
		MaxRetry: 3,
		Payload: []byte(fmt.Sprintf(`{
			"template": "payment_receipt",
			"payment_id": "%s"
		}`, paymentID)),
	}

	return s.jobQueue.Enqueue(ctx, job)
}

// Helper function to check if a slice contains a value
func contains(slice []string, value string) bool {
	for _, item := range slice {
		if item == value {
			return true
		}
	}
	return false
}
