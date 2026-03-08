package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// handleStripeWebhook receives Stripe webhook events, verifies the signature,
// and forwards the payload to the orders service for processing.
func handleStripeWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	secret := conf.StripeWebhookSecret
	if secret == "" {
		log.Println("WARN: STRIPE_WEBHOOK_SECRET not set — webhook disabled")
		http.Error(w, "webhook not configured", http.StatusServiceUnavailable)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	sigHeader := r.Header.Get("Stripe-Signature")
	if sigHeader == "" {
		http.Error(w, "missing Stripe-Signature header", http.StatusBadRequest)
		return
	}

	if !verifyStripeSignature(body, sigHeader, secret) {
		log.Println("WARN: Stripe webhook signature verification failed")
		http.Error(w, "invalid signature", http.StatusForbidden)
		return
	}

	var event struct {
		Type string          `json:"type"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &event); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	log.Printf("Stripe webhook received: %s", event.Type)

	switch event.Type {
	case "checkout.session.completed", "payment_intent.succeeded":
		if err := forwardToOrders(body); err != nil {
			log.Printf("WARN: failed to forward webhook to orders: %v", err)
		}
	default:
		log.Printf("Stripe event %s — acknowledged (no action)", event.Type)
	}

	respond(w, 200, map[string]string{"received": "true"})
}

func forwardToOrders(body []byte) error {
	url := conf.OrdersURL + "/webhooks/stripe"
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-From", "gateway")

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("orders returned %d", resp.StatusCode)
	}
	return nil
}

// verifyStripeSignature checks the Stripe-Signature header using HMAC-SHA256.
func verifyStripeSignature(payload []byte, sigHeader, secret string) bool {
	parts := strings.Split(sigHeader, ",")
	var timestamp, sig string
	for _, part := range parts {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "t":
			timestamp = kv[1]
		case "v1":
			sig = kv[1]
		}
	}

	if timestamp == "" || sig == "" {
		return false
	}

	signed := timestamp + "." + string(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signed))
	expected := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(expected), []byte(sig))
}

func handleStripeStatus(w http.ResponseWriter, r *http.Request) {
	configured := conf.StripeWebhookSecret != ""
	webhookURL := ""
	if conf.PublicURL != "" {
		webhookURL = conf.PublicURL + "/webhooks/stripe"
	}
	respond(w, 200, map[string]interface{}{
		"stripe_webhook_configured": configured,
		"webhook_url":               webhookURL,
	})
}
