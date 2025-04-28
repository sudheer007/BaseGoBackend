package razorpay

import (
	"errors"
)

// CreateSubscription creates a new subscription
func (c *Client) CreateSubscription(req SubscriptionRequest) (map[string]interface{}, error) {
	if req.PlanID == "" {
		return nil, errors.New("plan ID is required")
	}

	data := map[string]interface{}{
		"plan_id":         req.PlanID,
		"customer_notify": req.CustomerNotify,
	}

	if req.TotalCount > 0 {
		data["total_count"] = req.TotalCount
	}

	if req.StartAt != nil {
		data["start_at"] = req.StartAt.Unix()
	}

	if req.CustomerID != "" {
		data["customer_id"] = req.CustomerID
	}

	if len(req.Notes) > 0 {
		data["notes"] = req.Notes
	}

	return c.rzp.Subscription.Create(data, nil)
}

// GetSubscription retrieves a subscription by its ID
func (c *Client) GetSubscription(subscriptionID string) (map[string]interface{}, error) {
	if subscriptionID == "" {
		return nil, errors.New("subscription ID is required")
	}

	return c.rzp.Subscription.Fetch(subscriptionID, nil, nil)
}

// CancelSubscription cancels an active subscription
func (c *Client) CancelSubscription(subscriptionID string, cancelAtEnd bool) (map[string]interface{}, error) {
	if subscriptionID == "" {
		return nil, errors.New("subscription ID is required")
	}

	data := map[string]interface{}{
		"cancel_at_cycle_end": cancelAtEnd,
	}

	return c.rzp.Subscription.Cancel(subscriptionID, data, nil)
}

// PauseSubscription pauses a subscription
func (c *Client) PauseSubscription(subscriptionID string, pauseAt string) (map[string]interface{}, error) {
	if subscriptionID == "" {
		return nil, errors.New("subscription ID is required")
	}

	data := map[string]interface{}{}
	if pauseAt != "" {
		data["pause_at"] = pauseAt
	}

	return c.rzp.Subscription.Pause(subscriptionID, data, nil)
}

// ResumeSubscription resumes a paused subscription
func (c *Client) ResumeSubscription(subscriptionID string, resumeAt string) (map[string]interface{}, error) {
	if subscriptionID == "" {
		return nil, errors.New("subscription ID is required")
	}

	data := map[string]interface{}{}
	if resumeAt != "" {
		data["resume_at"] = resumeAt
	}

	return c.rzp.Subscription.Resume(subscriptionID, data, nil)
}
