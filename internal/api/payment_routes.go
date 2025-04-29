package api

import (
	"net/http"

	"gobackend/internal/middleware"
	"gobackend/internal/services"

	"github.com/gin-gonic/gin"
)

// RegisterPaymentRoutes registers payment-related routes
func RegisterPaymentRoutes(r *gin.Engine, paymentSvc *services.PaymentService, authMiddleware *middleware.AuthMiddleware) {
	// Skip if payment service is not available
	if paymentSvc == nil {
		return
	}

	// Create payment routes group
	paymentGroup := r.Group("/api/v1/payments")
	
	// Add authentication middleware
	paymentGroup.Use(authMiddleware.Authenticate())

	// Payment processing endpoints
	paymentGroup.POST("/process", handleProcessPayment(paymentSvc))
	paymentGroup.POST("/verify", handleVerifyPayment(paymentSvc))
	paymentGroup.GET("/:id", handleGetPayment(paymentSvc))

	// Subscription endpoints
	subscriptionGroup := r.Group("/api/v1/subscriptions")
	subscriptionGroup.Use(authMiddleware.Authenticate())
	
	subscriptionGroup.POST("/", handleCreateSubscription(paymentSvc))
	subscriptionGroup.GET("/:id", handleGetSubscription(paymentSvc))
	subscriptionGroup.POST("/:id/cancel", handleCancelSubscription(paymentSvc))

	// Webhook endpoint (no authentication required)
	r.POST("/api/v1/webhooks/payment", handlePaymentWebhook(paymentSvc))
}

// handleProcessPayment handles payment processing
func handleProcessPayment(paymentSvc *services.PaymentService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req services.PaymentRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
			return
		}

		// Get user ID from context
		userID, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
			return
		}
		req.UserID = userID.(string)

		// Process payment
		resp, err := paymentSvc.ProcessPayment(c.Request.Context(), req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process payment: " + err.Error()})
			return
		}

		c.JSON(http.StatusOK, resp)
	}
}

// handleVerifyPayment handles payment verification
func handleVerifyPayment(paymentSvc *services.PaymentService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req services.PaymentVerificationRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
			return
		}

		// Verify payment
		err := paymentSvc.VerifyPayment(c.Request.Context(), req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Payment verification failed: " + err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"status": "success", "message": "Payment verified successfully"})
	}
}

// handleGetPayment handles retrieving payment details
func handleGetPayment(paymentSvc *services.PaymentService) gin.HandlerFunc {
	return func(c *gin.Context) {
		paymentID := c.Param("id")
		if paymentID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Payment ID is required"})
			return
		}

		// Get payment details
		payment, err := paymentSvc.GetPaymentByID(c.Request.Context(), paymentID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve payment: " + err.Error()})
			return
		}

		c.JSON(http.StatusOK, payment)
	}
}

// handleCreateSubscription handles subscription creation
func handleCreateSubscription(paymentSvc *services.PaymentService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req services.SubscriptionRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
			return
		}

		// Get user ID from context
		userID, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
			return
		}
		req.UserID = userID.(string)

		// Create subscription
		resp, err := paymentSvc.CreateSubscription(c.Request.Context(), req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create subscription: " + err.Error()})
			return
		}

		c.JSON(http.StatusOK, resp)
	}
}

// handleGetSubscription handles retrieving subscription details
func handleGetSubscription(paymentSvc *services.PaymentService) gin.HandlerFunc {
	return func(c *gin.Context) {
		subscriptionID := c.Param("id")
		if subscriptionID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Subscription ID is required"})
			return
		}

		// Get subscription details
		subscription, err := paymentSvc.GetSubscriptionByID(c.Request.Context(), subscriptionID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve subscription: " + err.Error()})
			return
		}

		c.JSON(http.StatusOK, subscription)
	}
}

// handleCancelSubscription handles subscription cancellation
func handleCancelSubscription(paymentSvc *services.PaymentService) gin.HandlerFunc {
	return func(c *gin.Context) {
		subscriptionID := c.Param("id")
		if subscriptionID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Subscription ID is required"})
			return
		}

		// Get cancel at end parameter
		var req struct {
			CancelAtEnd bool `json:"cancel_at_end"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			// Default to immediate cancellation
			req.CancelAtEnd = false
		}

		// Cancel subscription
		err := paymentSvc.CancelSubscription(c.Request.Context(), subscriptionID, req.CancelAtEnd)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to cancel subscription: " + err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"status": "success", "message": "Subscription cancelled successfully"})
	}
}

// handlePaymentWebhook handles payment webhook events
func handlePaymentWebhook(paymentSvc *services.PaymentService) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get provider from request
		provider := c.Query("provider")
		if provider == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Provider is required"})
			return
		}

		// Get signature from header
		signature := c.GetHeader("X-Webhook-Signature")
		if signature == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Signature header is required"})
			return
		}

		// Read the raw body
		payload, err := c.GetRawData()
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read request body"})
			return
		}

		// Process webhook
		err = paymentSvc.HandleWebhook(c.Request.Context(), services.PaymentProvider(provider), payload, signature)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process webhook: " + err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"status": "success"})
	}
} 