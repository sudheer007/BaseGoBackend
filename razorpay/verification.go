package razorpay

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
)

// VerifySignature verifies the Razorpay signature
func (c *Client) VerifySignature(signature, subscriptionID, paymentID string) error {
	data := paymentID + "|" + subscriptionID
	return c.verifySignatureData(signature, data)
}

// VerifyWebhookSignature verifies the signature from Razorpay webhooks
func (c *Client) VerifyWebhookSignature(payload []byte, signature string) error {
	if c.config.WebhookSecret == "" {
		return errors.New("webhook secret is not configured")
	}

	return c.verifySignatureDataWithSecret(signature, string(payload), c.config.WebhookSecret)
}

// VerifyPayment verifies a payment from the verification request
func (c *Client) VerifyPayment(req VerificationRequest) error {
	return c.VerifySignature(req.Signature, req.SubscriptionID, req.PaymentID)
}

// verifySignatureData verifies signature with the client secret
func (c *Client) verifySignatureData(signature, data string) error {
	return c.verifySignatureDataWithSecret(signature, data, c.secret)
}

// verifySignatureDataWithSecret is the core verification function
func (c *Client) verifySignatureDataWithSecret(signature, data, secret string) error {
	h := hmac.New(sha256.New, []byte(secret))
	_, err := h.Write([]byte(data))
	if err != nil {
		return err
	}

	expectedSignature := hex.EncodeToString(h.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(expectedSignature), []byte(signature)) != 1 {
		return errors.New("invalid signature")
	}

	return nil
}
