package razorpay

import (
	"time"
)

// PlanFrequency defines subscription billing frequency
type PlanFrequency string

const (
	FrequencyMonthly PlanFrequency = "monthly"
	FrequencyYearly  PlanFrequency = "yearly"
)

// PlanRequest represents the request to create a plan
type PlanRequest struct {
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Amount      int64             `json:"amount"` // in smallest currency unit (paisa for INR)
	Currency    string            `json:"currency"`
	Period      PlanFrequency     `json:"period"`
	Interval    int               `json:"interval"`
	Notes       map[string]string `json:"notes,omitempty"`
}

// SubscriptionRequest represents a request to create a subscription
type SubscriptionRequest struct {
	PlanID         string            `json:"plan_id"`
	TotalCount     int               `json:"total_count,omitempty"` // billing cycles
	StartAt        *time.Time        `json:"start_at,omitempty"`
	CustomerID     string            `json:"customer_id,omitempty"`
	CustomerNotify bool              `json:"customer_notify"`
	Notes          map[string]string `json:"notes,omitempty"`
}

// WebhookEvent represents an event from Razorpay webhooks
type WebhookEvent struct {
	Entity    string                 `json:"entity"`
	EventID   string                 `json:"event_id"`
	Contains  []string               `json:"contains"`
	Payload   map[string]interface{} `json:"payload"`
	CreatedAt int64                  `json:"created_at"`
}

// VerificationRequest contains the data needed to verify a payment
type VerificationRequest struct {
	PaymentID      string `json:"razorpay_payment_id"`
	SubscriptionID string `json:"razorpay_subscription_id"`
	Signature      string `json:"razorpay_signature"`
}
