package razorpay

import (
	"errors"
)

// CreatePlan creates a new subscription plan
func (c *Client) CreatePlan(req PlanRequest) (map[string]interface{}, error) {
	if req.Name == "" {
		return nil, errors.New("plan name is required")
	}

	if req.Amount <= 0 {
		return nil, errors.New("plan amount must be greater than zero")
	}

	// Use default currency if not provided
	if req.Currency == "" {
		req.Currency = c.config.Currency
	}

	// Plan period validation
	if req.Period != FrequencyMonthly && req.Period != FrequencyYearly {
		return nil, errors.New("plan period must be either monthly or yearly")
	}

	// Set interval based on period if not provided
	if req.Interval <= 0 {
		req.Interval = 1
	}

	data := map[string]interface{}{
		"period":   string(req.Period),
		"interval": req.Interval,
		"item": map[string]interface{}{
			"name":        req.Name,
			"description": req.Description,
			"amount":      req.Amount,
			"currency":    req.Currency,
		},
	}

	if len(req.Notes) > 0 {
		data["notes"] = req.Notes
	}

	return c.rzp.Plan.Create(data, nil)
}

// GetPlan retrieves a plan by its ID
func (c *Client) GetPlan(planID string) (map[string]interface{}, error) {
	if planID == "" {
		return nil, errors.New("plan ID is required")
	}

	return c.rzp.Plan.Fetch(planID, map[string]interface{}{}, map[string]string{})
}

// ListPlans retrieves all plans
func (c *Client) ListPlans(options map[string]interface{}) (map[string]interface{}, error) {
	return c.rzp.Plan.All(options, nil)
}
