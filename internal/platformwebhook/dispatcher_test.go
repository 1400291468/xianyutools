package platformwebhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDispatcherSignsInboundPayload(t *testing.T) {
	secret := "test-signing-secret"
	var received []byte
	var signature string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		received, err = io.ReadAll(r.Body)
		if err != nil { t.Fatal(err) }
		signature = r.Header.Get("X-Ydisks-Signature")
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	dispatcher := New(server.URL, secret)
	dispatcher.deliver(context.Background(), Event{YdisksAccountID: "account-1", MessageKey: "message-1", ChatID: "chat-1", BuyerID: "buyer-1", Text: "你好", MessageType: "text", Direction: "incoming"})

	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(received)
	if signature != hex.EncodeToString(mac.Sum(nil)) { t.Fatalf("signature = %q", signature) }
}

func TestDispatcherRejectsNonIncomingEvents(t *testing.T) {
	dispatcher := New("http://127.0.0.1", "secret")
	if dispatcher.Publish(Event{Direction: "outgoing", MessageKey: "message-1"}) { t.Fatal("outgoing event must not be queued") }
	if dispatcher.Publish(Event{Direction: "incoming"}) { t.Fatal("event without idempotency key must not be queued") }
}