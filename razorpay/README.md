# Razorpay Subscriptions for Go

A secure, well-structured Go package for handling Razorpay subscriptions. This module allows you to easily implement monthly and yearly subscription plans with secure payment handling.

## Features

- Create and manage subscription plans (monthly, yearly)
- Process subscriptions with secure signature validation
- Handle webhook events for subscription lifecycle
- Store user-specific notes with subscriptions
- Comprehensive security measures

## Installation

```bash
go get github.com/yourusername/razorpay
```

## Quick Start

```go
package main

import (
    "os"
    "github.com/yourusername/razorpay"
)

func main() {
    // Initialize client
    config := &razorpay.Config{
        WebhookSecret: os.Getenv("RAZORPAY_WEBHOOK_SECRET"),
        Currency:      "INR",
    }
    
    client := razorpay.NewClient(
        os.Getenv("RAZORPAY_KEY_ID"),
        os.Getenv("RAZORPAY_SECRET"),
        config,
    )
    
    // Create a monthly plan
    plan, err := client.CreatePlan(razorpay.PlanRequest{
        Name:        "Standard Monthly",
        Description: "Monthly subscription",
        Amount:      99900, // 999.00 INR
        Period:      razorpay.FrequencyMonthly,
        Interval:    1,
        Notes: map[string]string{
            "plan_type": "standard",
        },
    })
    
    // Create a subscription
    subscription, err := client.CreateSubscription(razorpay.SubscriptionRequest{
        PlanID:         plan["id"].(string),
        TotalCount:     12, 
        CustomerNotify: true,
        Notes: map[string]string{
            "user_id": "user_123",
        },
    })
    
    // Work with the subscription
    subscriptionID := subscription["id"].(string)
    // Use this ID in your checkout flow
}
```

## Security

This module implements multiple security measures:

1. **HMAC Signature Verification**: All payments and webhooks are verified using HMAC-SHA256 signatures
2. **Constant-time Comparison**: Prevents timing attacks when verifying signatures
3. **Environment Variables**: API keys are never hardcoded
4. **Input Validation**: Comprehensive validation before making API calls

## Frontend Integration

To complete the subscription flow, use Razorpay's JavaScript checkout:

```html
<script src="https://checkout.razorpay.com/v1/checkout.js"></script>
<script>
  const options = {
    key: "YOUR_KEY_ID",
    subscription_id: "sub_123456789",
    name: "Your Company",
    description: "Monthly Subscription",
    handler: function(response) {
      // Verify on server
      verifyPayment(
        response.razorpay_payment_id,
        response.razorpay_subscription_id,
        response.razorpay_signature
      );
    }
  };
  
  const rzp = new Razorpay(options);
  rzp.open();
</script>
```

## Webhooks

Register handlers for subscription events:

```go
webhookHandler := client.NewWebhookHandler()

webhookHandler.RegisterHandler("subscription.activated", func(event razorpay.WebhookEvent) error {
    // Handle subscription activation
    return nil
})

webhookHandler.RegisterHandler("subscription.charged", func(event razorpay.WebhookEvent) error {
    // Handle successful payment
    return nil
})

// Set up HTTP handler
http.HandleFunc("/webhooks/razorpay", webhookHandler.HandleRequest)
```

## Complete Example

See the `example` directory for a full working example with frontend checkout page.

## License

MIT

## Documentation

For more information, see the [Razorpay API Documentation](https://razorpay.com/docs/payments/subscriptions/integration-guide/). 