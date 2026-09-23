// Package platformwebhook delivers persisted inbound Xianyu messages to Yun800.
package platformwebhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

type Event struct {
	YdisksAccountID string `json:"ydisks_account_id"`
	MessageKey      string `json:"message_key"`
	ChatID          string `json:"chat_id"`
	BuyerID         string `json:"buyer_id"`
	BuyerName       string `json:"buyer_name,omitempty"`
	ItemID          string `json:"item_id,omitempty"`
	ItemTitle       string `json:"item_title,omitempty"`
	Text            string `json:"text,omitempty"`
	MessageType     string `json:"message_type"`
	Direction       string `json:"direction"`
}

type Dispatcher struct {
	url    string
	secret []byte
	client *http.Client
	queue  chan Event
}

func New(url, secret string) *Dispatcher {
	if strings.TrimSpace(url) == "" || strings.TrimSpace(secret) == "" { return nil }
	return &Dispatcher{url: url, secret: []byte(secret), client: &http.Client{Timeout: 10 * time.Second}, queue: make(chan Event, 256)}
}

func (d *Dispatcher) Publish(event Event) bool {
	if d == nil || event.Direction != "incoming" || event.MessageKey == "" { return false }
	select { case d.queue <- event: return true; default: return false }
}

func (d *Dispatcher) Run(ctx context.Context) {
	if d == nil { return }
	for {
		select {
		case <-ctx.Done(): return
		case event := <-d.queue: d.deliver(ctx, event)
		}
	}
}

func (d *Dispatcher) deliver(parent context.Context, event Event) {
	body, err := json.Marshal(event); if err != nil { return }
	for attempt := 0; attempt < 3; attempt++ {
		ctx, cancel := context.WithTimeout(parent, 10*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.url, bytes.NewReader(body))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Ydisks-Signature", signature(d.secret, body))
			response, callErr := d.client.Do(req)
			if response != nil { response.Body.Close() }
			if callErr == nil && response != nil && response.StatusCode >= 200 && response.StatusCode < 300 { cancel(); return }
		}
		cancel()
		if attempt < 2 { select { case <-parent.Done(): return; case <-time.After(time.Duration(1<<attempt) * time.Second): } }
	}
}

func signature(secret, body []byte) string { mac := hmac.New(sha256.New, secret); _, _ = mac.Write(body); return hex.EncodeToString(mac.Sum(nil)) }