package razorpay

// Config contains the configuration for the Razorpay client
type Config struct {
	WebhookSecret string
	Currency      string
	RetryAttempts int
}

// DefaultConfig returns default configuration values
func DefaultConfig() *Config {
	return &Config{
		Currency:      "INR",
		RetryAttempts: 3,
	}
}
