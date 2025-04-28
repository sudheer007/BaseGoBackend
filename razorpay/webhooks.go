package razorpay

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
)

// WebhookHandler handles Razorpay webhook events
type WebhookHandler struct {
	client   *Client
	handlers map[string]func(WebhookEvent) error
}

// NewWebhookHandler creates a new webhook handler
func (c *Client) NewWebhookHandler() *WebhookHandler {
	return &WebhookHandler{
		client:   c,
		handlers: make(map[string]func(WebhookEvent) error),
	}
}

// RegisterHandler registers a handler for a specific event
func (wh *WebhookHandler) RegisterHandler(event string, handler func(WebhookEvent) error) {
	wh.handlers[event] = handler
}

// HandleRequest processes an incoming webhook request
func (wh *WebhookHandler) HandleRequest(w http.ResponseWriter, r *http.Request) {
	// Verify HTTP method
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read request body
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	// Get signature from header
	signature := r.Header.Get("X-Razorpay-Signature")
	if signature == "" {
		http.Error(w, "Missing signature header", http.StatusBadRequest)
		return
	}

	// Verify signature
	err = wh.client.VerifyWebhookSignature(body, signature)
	if err != nil {
		http.Error(w, "Invalid signature", http.StatusBadRequest)
		return
	}

	// Parse event
	var event WebhookEvent
	if err := json.Unmarshal(body, &event); err != nil {
		http.Error(w, "Invalid event data", http.StatusBadRequest)
		return
	}

	// Handle the event
	err = wh.processEvent(event)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return success
	w.WriteHeader(http.StatusOK)
}

// processEvent processes a webhook event
func (wh *WebhookHandler) processEvent(event WebhookEvent) error {
	// Get handler for this event
	handler, ok := wh.handlers[event.Entity]
	if !ok {
		return errors.New("no handler registered for event: " + event.Entity)
	}

	// Call the handler
	return handler(event)
}
