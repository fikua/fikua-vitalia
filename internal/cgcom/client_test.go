package cgcom_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fikua/fikua-vitalia/internal/adapterstub"
	"github.com/fikua/fikua-vitalia/internal/cgcom"
)

type recorder struct {
	mu    sync.Mutex
	calls []cgcom.Call
}

func (r *recorder) RecordCall(_ context.Context, c cgcom.Call) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, c)
	return nil
}

func newClient(t *testing.T, token string) (*cgcom.Client, *recorder) {
	t.Helper()
	stub := &adapterstub.Stub{Token: "platform-token", PortalURL: "https://portal.test/"}
	srv := httptest.NewServer(stub.Handler())
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	rec := &recorder{}
	return cgcom.NewClient(u, &http.Client{Timeout: 5 * time.Second}, cgcom.StaticTokenSource(token), rec), rec
}

func problemOf(t *testing.T, err error) *cgcom.ProblemError {
	t.Helper()
	var pe *cgcom.ProblemError
	if !errors.As(err, &pe) {
		t.Fatalf("error %v is not a ProblemError", err)
	}
	return pe
}

func TestCreateEnrollment(t *testing.T) {
	c, rec := newClient(t, "platform-token")
	ctx := context.Background()

	first, err := c.CreateEnrollment(ctx, "12345678Z", "282812345")
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != http.StatusCreated || first.Enrollment.State != cgcom.Initiated || first.Enrollment.IssuancePortalURL == nil {
		t.Fatalf("first enrol = %d %+v", first.Status, first.Enrollment)
	}

	again, err := c.CreateEnrollment(ctx, "12345678Z", "282812345")
	if err != nil {
		t.Fatal(err)
	}
	if again.Status != http.StatusOK || again.Enrollment.ID != first.Enrollment.ID {
		t.Fatalf("repeat enrol = %d %s, want 200 with the same id", again.Status, again.Enrollment.ID)
	}

	has, err := c.CreateEnrollment(ctx, "12345678Z", "282812340")
	if err != nil {
		t.Fatal(err)
	}
	if has.Enrollment.State != cgcom.PendingConfirmation || has.Enrollment.DoctorID == nil {
		t.Fatalf("physician with DoctorID = %+v", has.Enrollment)
	}

	if len(rec.calls) != 3 || rec.calls[0].EnrollmentID != first.Enrollment.ID || rec.calls[0].Status != 201 {
		t.Fatalf("calls recorded = %+v", rec.calls)
	}
	for _, call := range rec.calls {
		if strings.Contains(call.RequestBody, "platform-token") || strings.Contains(call.ResponseBody, "platform-token") {
			t.Fatal("token leaked into the call log")
		}
	}
}

func TestProblems(t *testing.T) {
	ctx := context.Background()

	t.Run("invalid request", func(t *testing.T) {
		c, _ := newClient(t, "platform-token")
		_, err := c.CreateEnrollment(ctx, "12345678Z", "12")
		pe := problemOf(t, err)
		if pe.Status != 400 || pe.Problem.Type != "invalid_request" || len(pe.Problem.Violations) == 0 {
			t.Fatalf("got %+v", pe)
		}
	})
	t.Run("no token", func(t *testing.T) {
		c, rec := newClient(t, "")
		_, err := c.CreateEnrollment(ctx, "12345678Z", "282812345")
		if pe := problemOf(t, err); pe.Status != 401 || pe.Problem.Type != "authentication_required" {
			t.Fatalf("got %+v", pe)
		}
		if rec.calls[0].ProblemType != "authentication_required" {
			t.Fatalf("problem type not recorded: %+v", rec.calls[0])
		}
	})
	t.Run("wrong token", func(t *testing.T) {
		c, _ := newClient(t, "stolen")
		_, err := c.GetEnrollment(ctx, "6a0d7f3c-2b1e-4e8a-9c55-1f0b2d3e4a5b")
		if pe := problemOf(t, err); pe.Status != 401 || pe.Problem.Type != "invalid_token" {
			t.Fatalf("got %+v", pe)
		}
	})
	t.Run("not found", func(t *testing.T) {
		c, _ := newClient(t, "platform-token")
		_, err := c.GetEnrollment(ctx, "6a0d7f3c-2b1e-4e8a-9c55-1f0b2d3e4a5b")
		if pe := problemOf(t, err); pe.Status != 404 || pe.Problem.Type != "enrollment_not_found" {
			t.Fatalf("got %+v", pe)
		}
	})
	t.Run("issuer unavailable honours Retry-After", func(t *testing.T) {
		c, rec := newClient(t, "platform-token")
		_, err := c.CreateEnrollment(ctx, "12345678Z", "999000001")
		pe := problemOf(t, err)
		if pe.Status != 503 || pe.Problem.Type != "issuer_unavailable" || !pe.HasRetry || pe.RetryAfter != 30*time.Second {
			t.Fatalf("got %+v", pe)
		}
		if rec.calls[0].RetryAfter != "30" {
			t.Fatalf("Retry-After not recorded: %+v", rec.calls[0])
		}
	})
	t.Run("state conflict", func(t *testing.T) {
		c, _ := newClient(t, "platform-token")
		res, err := c.CreateEnrollment(ctx, "12345678Z", "282812345") // INITIATED
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.Decide(ctx, res.Enrollment.ID, cgcom.Confirm)
		if pe := problemOf(t, err); pe.Status != 409 || pe.Problem.Type != "enrollment_state_conflict" {
			t.Fatalf("got %+v", pe)
		}
	})
	t.Run("invalid id never reaches the adapter", func(t *testing.T) {
		c, rec := newClient(t, "platform-token")
		if _, err := c.GetEnrollment(ctx, "../../admin"); err == nil {
			t.Fatal("expected an error")
		}
		if len(rec.calls) != 0 {
			t.Fatal("a call was made")
		}
	})
}

func TestConfirmAndCancelAreIdempotent(t *testing.T) {
	c, _ := newClient(t, "platform-token")
	ctx := context.Background()
	res, err := c.CreateEnrollment(ctx, "X1234567L", "282812340") // PENDING_CONFIRMATION
	if err != nil {
		t.Fatal(err)
	}
	id := res.Enrollment.ID
	for range 2 {
		got, err := c.Decide(ctx, id, cgcom.Confirm)
		if err != nil || got.Enrollment.State != cgcom.Completed {
			t.Fatalf("confirm = %+v, %v", got.Enrollment, err)
		}
	}
	if _, err := c.Cancel(ctx, id); problemOf(t, err).Status != 409 {
		t.Fatal("cancelling a COMPLETED enrollment must be a conflict")
	}

	other, _ := c.CreateEnrollment(ctx, "X1234567L", "282812345")
	for range 2 {
		got, err := c.Cancel(ctx, other.Enrollment.ID)
		if err != nil || got.Enrollment.State != cgcom.Cancelled {
			t.Fatalf("cancel = %+v, %v", got.Enrollment, err)
		}
	}
}
