package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/fikua/fikua-vitalia/internal/cgcom"
	"github.com/fikua/fikua-vitalia/internal/store"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// Sink stores received requests.
type Sink interface {
	RecordWebhook(ctx context.Context, ev store.WebhookEvent) (duplicate bool, err error)
}

// Receiver is the HTTP handler of the webhook endpoint. It only verifies and
// stores; processing happens afterwards, outside the request.
type Receiver struct {
	Secret    []byte
	Tolerance time.Duration
	Sink      Sink
	Notify    func() // wakes the processor; may be nil
	Logger    *slog.Logger
	Now       func() time.Time
}

const (
	maxBody         = 1 << 20 // 1 MiB
	maxRejectedBody = 4 << 10 // what we keep of an unsigned body, for diagnosis
)

func (h *Receiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	now := time.Now
	if h.Now != nil {
		now = h.Now
	}
	received := now()

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeProblem(w, http.StatusRequestEntityTooLarge, "payload_too_large", "The body exceeds 1 MiB.")
			return
		}
		writeProblem(w, http.StatusBadRequest, "invalid_request", "The body could not be read.")
		return
	}

	// Verify on the raw bytes, before parsing anything.
	if verr := cgcom.Verify(r.Header.Get(cgcom.SignatureHeader), body, h.Secret, received, h.Tolerance); verr != nil {
		kept := body
		if len(kept) > maxRejectedBody {
			kept = kept[:maxRejectedBody]
		}
		_, err := h.Sink.RecordWebhook(r.Context(), store.WebhookEvent{
			ReceivedAt: received, SignatureValid: false, SignatureError: verr.Error(),
			RawBody: string(kept), Status: store.WebhookRejected,
		})
		if err != nil {
			h.Logger.Error("store rejected webhook", "err", err)
		}
		h.Logger.Warn("webhook rejected", "reason", verr.Error(), "remote", r.RemoteAddr)
		writeProblem(w, http.StatusUnauthorized, "invalid_signature", "Missing, malformed or wrong signature.")
		return
	}

	var ev cgcom.Event
	if err := json.Unmarshal(body, &ev); err != nil || !cgcom.ValidID(ev.EventID) || !cgcom.ValidID(ev.Enrollment.ID) {
		// Signed by the adapter but not an event we can read: keep it as
		// evidence and answer 400 so the adapter's retries and alert show it.
		_, serr := h.Sink.RecordWebhook(r.Context(), store.WebhookEvent{
			ReceivedAt: received, SignatureValid: true, RawBody: string(body),
			Status: store.WebhookInvalid, StatusDetail: "missing or invalid event_id or enrollment.id",
		})
		if serr != nil {
			h.Logger.Error("store invalid webhook", "err", serr)
		}
		writeProblem(w, http.StatusBadRequest, "invalid_request", "The event has no valid event_id or enrollment.id.")
		return
	}

	occurred := ""
	if !ev.OccurredAt.IsZero() {
		occurred = ev.OccurredAt.UTC().Format(time.RFC3339Nano)
	}
	duplicate, err := h.Sink.RecordWebhook(r.Context(), store.WebhookEvent{
		EventID: ev.EventID, ReceivedAt: received, SignatureValid: true, Event: ev.Event,
		EnrollmentID: ev.Enrollment.ID, OccurredAt: occurred, RawBody: string(body), Status: store.WebhookPending,
	})
	if err != nil {
		// 5xx makes the adapter retry with the same event_id: nothing is lost.
		h.Logger.Error("store webhook", "err", err, "event_id", ev.EventID)
		writeProblem(w, http.StatusServiceUnavailable, "storage_unavailable", "Try again later.")
		return
	}
	h.Logger.Info("webhook received", "event_id", ev.EventID, "event", ev.Event, "enrollment_id", ev.Enrollment.ID, "duplicate", duplicate)
	if !duplicate && h.Notify != nil {
		h.Notify()
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"received": true, "duplicate": duplicate})
}

func writeProblem(w http.ResponseWriter, status int, typ, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(cgcom.Problem{Type: typ, Title: http.StatusText(status), Status: status, Detail: detail})
}
