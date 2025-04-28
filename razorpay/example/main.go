package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/yourusername/razorpay"
)

func main() {
	// Initialize client with environment variables
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
	monthlyPlan, err := client.CreatePlan(razorpay.PlanRequest{
		Name:        "Standard Monthly",
		Description: "Monthly subscription for standard features",
		Amount:      99900, // 999.00 INR in paise
		Period:      razorpay.FrequencyMonthly,
		Interval:    1,
		Notes: map[string]string{
			"plan_type": "standard",
			"features":  "basic,premium",
		},
	})
	if err != nil {
		log.Fatalf("Failed to create monthly plan: %v", err)
	}

	// Create a yearly plan with discount
	yearlyPlan, err := client.CreatePlan(razorpay.PlanRequest{
		Name:        "Standard Yearly",
		Description: "Yearly subscription with 20% discount",
		Amount:      959040, // 9590.40 INR in paise (20% off monthly * 12)
		Period:      razorpay.FrequencyYearly,
		Interval:    1,
		Notes: map[string]string{
			"plan_type": "standard",
			"features":  "basic,premium",
			"discount":  "20%",
		},
	})
	if err != nil {
		log.Fatalf("Failed to create yearly plan: %v", err)
	}

	// Set up webhook handler
	webhookHandler := client.NewWebhookHandler()

	// Register handlers for different subscription events
	webhookHandler.RegisterHandler("subscription.activated", handleSubscriptionActivated)
	webhookHandler.RegisterHandler("subscription.charged", handleSubscriptionCharged)
	webhookHandler.RegisterHandler("subscription.halted", handleSubscriptionHalted)
	webhookHandler.RegisterHandler("subscription.cancelled", handleSubscriptionCancelled)

	// Set up HTTP server for webhooks
	http.HandleFunc("/webhooks/razorpay", webhookHandler.HandleRequest)

	// Set up routes for subscription management
	http.HandleFunc("/create-subscription", func(w http.ResponseWriter, r *http.Request) {
		createSubscriptionHandler(w, r, client)
	})

	http.HandleFunc("/verify-payment", func(w http.ResponseWriter, r *http.Request) {
		verifyPaymentHandler(w, r, client)
	})

	// Serve the checkout page
	http.HandleFunc("/", serveCheckoutPage)

	fmt.Println("Monthly plan created with ID:", monthlyPlan["id"])
	fmt.Println("Yearly plan created with ID:", yearlyPlan["id"])
	fmt.Println("Starting server on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// Event handlers for webhooks
func handleSubscriptionActivated(event razorpay.WebhookEvent) error {
	fmt.Println("Subscription activated:", event.Payload["subscription"].(map[string]interface{})["id"])
	// Update user subscription status in your database
	return nil
}

func handleSubscriptionCharged(event razorpay.WebhookEvent) error {
	fmt.Println("Subscription payment successful:", event.Payload["payment"].(map[string]interface{})["id"])
	// Update payment status in your database
	return nil
}

func handleSubscriptionHalted(event razorpay.WebhookEvent) error {
	fmt.Println("Subscription payment failed:", event.Payload["subscription"].(map[string]interface{})["id"])
	// Handle failed payment
	return nil
}

func handleSubscriptionCancelled(event razorpay.WebhookEvent) error {
	fmt.Println("Subscription cancelled:", event.Payload["subscription"].(map[string]interface{})["id"])
	// Update subscription status in your database
	return nil
}

// HTTP handlers
func createSubscriptionHandler(w http.ResponseWriter, r *http.Request, client *razorpay.Client) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	planID := r.Form.Get("plan_id")
	if planID == "" {
		http.Error(w, "Plan ID is required", http.StatusBadRequest)
		return
	}

	// Create subscription
	subscription, err := client.CreateSubscription(razorpay.SubscriptionRequest{
		PlanID:         planID,
		TotalCount:     12, // For 1 year (12 months) or 1 for yearly
		CustomerNotify: true,
		Notes: map[string]string{
			"user_id": r.Form.Get("user_id"),
		},
	})

	if err != nil {
		http.Error(w, "Failed to create subscription: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Return subscription ID to client
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"subscription_id": "%s", "key_id": "%s"}`, subscription["id"], client.GetKeyID())
}

func verifyPaymentHandler(w http.ResponseWriter, r *http.Request, client *razorpay.Client) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	// Create verification request
	verificationReq := razorpay.VerificationRequest{
		PaymentID:      r.Form.Get("razorpay_payment_id"),
		SubscriptionID: r.Form.Get("razorpay_subscription_id"),
		Signature:      r.Form.Get("razorpay_signature"),
	}

	// Verify payment
	err = client.VerifyPayment(verificationReq)
	if err != nil {
		http.Error(w, "Payment verification failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Return success response
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"success": true, "message": "Payment verified successfully"}`)
}

func serveCheckoutPage(w http.ResponseWriter, r *http.Request) {
	html := `
<!DOCTYPE html>
<html>
<head>
    <title>Subscription Checkout</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; color: #333; }
        .container { max-width: 800px; margin: 0 auto; }
        .plan-box { border: 1px solid #ddd; padding: 20px; margin-bottom: 20px; border-radius: 4px; }
        .plan-title { font-size: 24px; margin-bottom: 10px; }
        .plan-price { font-size: 20px; color: #2a8eff; margin-bottom: 15px; }
        .plan-features { margin-bottom: 20px; }
        .feature-item { margin-bottom: 5px; }
        .subscribe-btn { background-color: #2a8eff; color: white; border: none; padding: 10px 20px; 
                         font-size: 16px; cursor: pointer; border-radius: 4px; }
        .subscribe-btn:hover { background-color: #0c74e0; }
        .plan-discount { color: #e02a2a; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Choose Your Subscription Plan</h1>
        
        <div class="plan-box">
            <div class="plan-title">Standard Monthly</div>
            <div class="plan-price">₹999/month</div>
            <div class="plan-features">
                <div class="feature-item">✓ Basic Features</div>
                <div class="feature-item">✓ Premium Support</div>
                <div class="feature-item">✓ Access to all tools</div>
            </div>
            <button class="subscribe-btn" onclick="subscribe('MONTHLY_PLAN_ID')">Subscribe Monthly</button>
        </div>
        
        <div class="plan-box">
            <div class="plan-title">Standard Yearly</div>
            <div class="plan-price">₹9,590/year <span class="plan-discount">(Save 20%)</span></div>
            <div class="plan-features">
                <div class="feature-item">✓ All Monthly Features</div>
                <div class="feature-item">✓ Priority Support</div>
                <div class="feature-item">✓ Exclusive Early Access</div>
            </div>
            <button class="subscribe-btn" onclick="subscribe('YEARLY_PLAN_ID')">Subscribe Yearly</button>
        </div>
    </div>

    <script src="https://checkout.razorpay.com/v1/checkout.js"></script>
    <script>
        function subscribe(planId) {
            // Replace with actual plan IDs
            planId = planId === 'MONTHLY_PLAN_ID' ? 'plan_XXXXXXXXXXXXXX' : 'plan_YYYYYYYYYYYYYY';
            
            // Create subscription on server
            fetch('/create-subscription', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'plan_id=' + planId + '&user_id=user_123'
            })
            .then(response => response.json())
            .then(data => {
                const options = {
                    key: data.key_id,
                    subscription_id: data.subscription_id,
                    name: "Your Company",
                    description: "Subscription Payment",
                    theme: {
                        color: "#2a8eff"
                    },
                    prefill: {
                        name: "Customer Name",
                        email: "customer@example.com",
                        contact: "+919876543210"
                    },
                    notes: {
                        user_id: "user_123"
                    },
                    handler: function(response) {
                        // Verify payment on server
                        verifyPayment(response);
                    }
                };
                
                const rzp = new Razorpay(options);
                rzp.open();
            })
            .catch(error => {
                console.error('Error creating subscription:', error);
                alert('Failed to create subscription. Please try again.');
            });
        }
        
        function verifyPayment(response) {
            const formData = new URLSearchParams();
            formData.append('razorpay_payment_id', response.razorpay_payment_id);
            formData.append('razorpay_subscription_id', response.razorpay_subscription_id);
            formData.append('razorpay_signature', response.razorpay_signature);
            
            fetch('/verify-payment', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert('Subscription successful! Thank you for subscribing.');
                    // Redirect to dashboard or confirmation page
                    // window.location.href = '/dashboard';
                } else {
                    alert('Payment verification failed. Please contact support.');
                }
            })
            .catch(error => {
                console.error('Error verifying payment:', error);
                alert('Failed to verify payment. Please contact support.');
            });
        }
    </script>
</body>
</html>
`
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}
