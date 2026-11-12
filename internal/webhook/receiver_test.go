package webhook_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fikua/fikua-vitalia/internal/store"
	"github.com/fikua/fikua-vitalia/internal/webhook"
)

var secret = []byte("0123456789abcdef0123456789abcdef")

func newReceiver(t *testing.T) (*webhook.Receiver, *store.Store, *int) {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	notified := 0
	return &webhook.Receiver{Secret: secret, Tolerance: 5 * time.Minute, Sink: st,
		Notify: func() { notified++ }, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}, st, &notified
}

func post(h http.Handler, body []byte, header string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/webhooks/enrollments", bytes.NewReader(body))
	if header != "" {
		req.Header.Set(webhook.SignatureHeader, header)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

const event = `{"event_id":"11111111-1111-4111-8111-111111111111","event":"enrollment_state_changed","occurred_at":"2026-11-12T10:00:00Z",
"enrollment":{"id":"22222222-2222-4222-8222-222222222222","state":"PENDING_CONFIRMATION","collegiate_number":"282812340"}}`

func TestReceiverStoresSignedEventOnce(t *testing.T) {
	h, st, notified := newReceiver(t)
	body := []byte(event)

	first := post(h, body, webhook.Sign(secret, time.Now(), body))
	if first.Code != http.StatusOK || !strings.Contains(first.Body.String(), `"duplicate":false`) {
		t.Fatalf("first delivery: %d %s", first.Code, first.Body)
	}
	again := post(h, body, webhook.Sign(secret, time.Now(), body)) // adapter retry, same event_id
	if again.Code != http.StatusOK || !strings.Contains(again.Body.String(), `"duplicate":true`) {
		t.Fatalf("retry: %d %s", again.Code, again.Body)
	}

	events, _ := st.RecentWebhooks(context.Background(), 10)
	if len(events) != 1 || events[0].Status != store.WebhookPending || !events[0].SignatureValid {
		t.Fatalf("stored events = %+v", events)
	}
	if *notified != 1 {
		t.Fatalf("processor notified %d times, want 1", *notified)
	}
}

func TestReceiverRejectsBadSignatureWithoutProcessing(t *testing.T) {
	h, st, notified := newReceiver(t)
	body := []byte(event)
	cases := map[string]string{
		"missing":      "",
		"wrong secret": webhook.Sign([]byte("not-the-secret-not-the-secret-xx"), time.Now(), body),
		"too old":      webhook.Sign(secret, time.Now().Add(-10*time.Minute), body),
		"malformed":    "v1=abc",
	}
	for name, header := range cases {
		if rec := post(h, body, header); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", name, rec.Code)
		}
	}
	events, _ := st.RecentWebhooks(context.Background(), 10)
	if len(events) != len(cases) {
		t.Fatalf("stored %d rejected requests, want %d", len(events), len(cases))
	}
	for _, ev := range events {
		if ev.Status != store.WebhookRejected || ev.SignatureValid || ev.EventID != "" {
			t.Errorf("rejected request stored as %+v", ev)
		}
	}
	if *notified != 0 {
		t.Fatal("processor notified for a rejected request")
	}
}

func TestReceiverSignedButInvalidEvent(t *testing.T) {
	h, _, _ := newReceiver(t)
	body := []byte(`{"event":"enrollment_state_changed"}`)
	if rec := post(h, body, webhook.Sign(secret, time.Now(), body)); rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rec.Code)
	}
}

func TestReceiverBodyTooLarge(t *testing.T) {
	h, _, _ := newReceiver(t)
	body := bytes.Repeat([]byte("a"), 2<<20)
	if rec := post(h, body, webhook.Sign(secret, time.Now(), body)); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d, want 413", rec.Code)
	}
}
