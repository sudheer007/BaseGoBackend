package razorpay

import (
	"github.com/razorpay/razorpay-go"
)

// Client wraps the Razorpay API client
type Client struct {
	rzp    *razorpay.Client
	keyID  string
	secret string
	config *Config
}

// NewClient creates a new Razorpay client instance
func NewClient(keyID, secret string, config *Config) *Client {
	if config == nil {
		config = DefaultConfig()
	}

	return &Client{
		rzp:    razorpay.NewClient(keyID, secret),
		keyID:  keyID,
		secret: secret,
		config: config,
	}
}

// GetKeyID returns the Razorpay API key ID
func (c *Client) GetKeyID() string {
	return c.keyID
}
