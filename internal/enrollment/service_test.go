package enrollment_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/fikua/fikua-vitalia/internal/adapter"
	"github.com/fikua/fikua-vitalia/internal/adapterstub"
	"github.com/fikua/fikua-vitalia/internal/enrollment"
	"github.com/fikua/fikua-vitalia/internal/store"
	"github.com/fikua/fikua-vitalia/internal/webhook"
)

var secret = []byte("0123456789abcdef0123456789abcdef")

type env struct {
	stub *adapterstub.Stub
	st   *store.Store
	svc  *enrollment.Service
}

// newEnv wires the platform (store, client, service, webhook receiver) to the
// adapter stub, which posts its webhooks to the platform's receiver.
func newEnv(t *testing.T, refreshOnWebhook bool) *env {
	t.Helper()
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	stub := &adapterstub.Stub{Token: "tok", PortalURL: "https://portal.test/", WebhookSecret: secret}
	adapterSrv := httptest.NewServer(stub.Handler())
	t.Cleanup(adapterSrv.Close)
	u, _ := url.Parse(adapterSrv.URL)

	client := adapter.NewClient(u, &http.Client{Timeout: 5 * time.Second}, adapter.StaticTokenSource("tok"), st)
	svc := enrollment.New(st, client, logger, refreshOnWebhook)
	receiver := &webhook.Receiver{Secret: secret, Tolerance: 5 * time.Minute, Sink: st, Logger: logger}
	platformSrv := httptest.NewServer(receiver)
	t.Cleanup(platformSrv.Close)
	stub.WebhookURL = platformSrv.URL

	return &env{stub: stub, st: st, svc: svc}
}

func (e *env) enrol(t *testing.T, coll string) (store.Practitioner, store.Enrollment) {
	t.Helper()
	p, err := e.svc.Enrol(context.Background(), enrollment.NewPractitioner{
		FullName: "Laia Puig Soler", AdministrativeNumber: "12345678-z", CollegiateNumber: coll})
	if err != nil {
		t.Fatal(err)
	}
	list, err := e.st.EnrollmentsOf(context.Background(), p.ID)
	if err != nil || len(list) != 1 {
		t.Fatalf("enrollments = %v, %v", list, err)
	}
	return p, list[0]
}

func (e *env) act(t *testing.T, id, action string) {
	t.Helper()
	sent, err := e.stub.Act(context.Background(), id, action)
	if err != nil || sent.Err != nil || sent.Status != http.StatusOK {
		t.Fatalf("%s: %v %+v", action, err, sent)
	}
	e.svc.ProcessPending(context.Background())
}

func (e *env) state(t *testing.T, id string) store.Enrollment {
	t.Helper()
	got, err := e.st.Enrollment(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestFullFlowWithoutDoctorID(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	p, enr := e.enrol(t, "282812345")
	if p.AdministrativeNumber != "12345678Z" {
		t.Fatalf("administrative number not normalised: %q", p.AdministrativeNumber)
	}
	if enr.State != adapter.Initiated {
		t.Fatalf("state = %s", enr.State)
	}

	e.act(t, enr.ID, "mismatch")
	if got := e.state(t, enr.ID); got.State != adapter.PendingAuthSources || *got.Decoded().AuthSourcesCause != "identity_mismatch" {
		t.Fatalf("after mismatch = %s", got.State)
	}

	e.act(t, enr.ID, "obtain")
	if got := e.state(t, enr.ID); got.State != adapter.PendingConfirmation || got.Decoded().DoctorID == nil {
		t.Fatalf("after obtain = %s", got.State)
	}

	if err := e.svc.Decide(ctx, enr.ID, adapter.Confirm); err != nil {
		t.Fatal(err)
	}
	if got := e.state(t, enr.ID); got.State != adapter.Completed {
		t.Fatalf("after confirm = %s", got.State)
	}

	hooks, _ := e.st.WebhooksOf(ctx, enr.ID)
	if len(hooks) != 2 || hooks[0].Status != store.WebhookApplied || hooks[1].Status != store.WebhookApplied {
		t.Fatalf("webhooks = %+v", hooks)
	}
}

func TestRenewalFlow(t *testing.T) {
	e := newEnv(t, false)
	_, enr := e.enrol(t, "282812340") // already has a DoctorID
	if enr.State != adapter.PendingConfirmation {
		t.Fatalf("state = %s", enr.State)
	}
	if err := e.svc.Decide(context.Background(), enr.ID, adapter.Confirm); err != nil {
		t.Fatal(err)
	}
	firstProcedure := e.state(t, enr.ID).Decoded().DoctorID.ProcedureID

	e.act(t, enr.ID, "renew")
	got := e.state(t, enr.ID)
	if got.State != adapter.Completed || got.InvalidatedReason != "renew" || got.InvalidatedProcedureID != firstProcedure {
		t.Fatalf("after renew = %s %q %q", got.State, got.InvalidatedReason, got.InvalidatedProcedureID)
	}

	e.act(t, enr.ID, "obtain") // the physician gets the renewed DoctorID
	got = e.state(t, enr.ID)
	if got.State != adapter.PendingConfirmation || got.InvalidatedReason != "" {
		t.Fatalf("after new DoctorID = %s, invalidated %q", got.State, got.InvalidatedReason)
	}
}

func TestOutOfOrderWebhookDoesNotMoveStateBack(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	_, enr := e.enrol(t, "282812345")

	older := time.Now().UTC().Add(-time.Minute)
	newer := time.Now().UTC()
	cause := "identity_mismatch"
	late := adapter.Event{EventID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Event: adapter.EventStateChanged, OccurredAt: older,
		Enrollment: adapter.Enrollment{ID: enr.ID, State: adapter.PendingAuthSources, CollegiateNumber: "282812345", AuthSourcesCause: &cause, UpdatedAt: &older}}
	fresh := adapter.Event{EventID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", Event: adapter.EventStateChanged, OccurredAt: newer,
		Enrollment: adapter.Enrollment{ID: enr.ID, State: adapter.Expired, CollegiateNumber: "282812345", UpdatedAt: &newer}}

	if s := e.stub.SendEvent(ctx, fresh); s.Status != http.StatusOK {
		t.Fatalf("send fresh: %+v", s)
	}
	e.svc.ProcessPending(ctx)
	if s := e.stub.SendEvent(ctx, late); s.Status != http.StatusOK {
		t.Fatalf("send late: %+v", s)
	}
	if s := e.stub.SendEvent(ctx, late); s.Status != http.StatusOK { // and a retry of it
		t.Fatalf("send late again: %+v", s)
	}
	e.svc.ProcessPending(ctx)

	if got := e.state(t, enr.ID); got.State != adapter.Expired {
		t.Fatalf("state = %s, want EXPIRED", got.State)
	}
	hooks, _ := e.st.WebhooksOf(ctx, enr.ID)
	if len(hooks) != 2 || hooks[0].Status != store.WebhookStale {
		t.Fatalf("webhooks = %+v", hooks)
	}
}

func TestWebhookForUnknownEnrollmentIsKeptAndReconciled(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()

	// The stub opens the enrolment, but the platform has not stored it yet
	// (the webhook overtakes the POST response).
	p, err := e.st.FindOrCreatePractitioner(ctx, store.Practitioner{FullName: "Pau Vidal", AdministrativeNumber: "Y1234567X", CollegiateNumber: "282812345"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	early := adapter.Event{EventID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", Event: adapter.EventStateChanged, OccurredAt: now,
		Enrollment: adapter.Enrollment{ID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", State: adapter.Expired, CollegiateNumber: "282812345", UpdatedAt: &now}}
	if s := e.stub.SendEvent(ctx, early); s.Status != http.StatusOK {
		t.Fatalf("an unknown enrolment must still be acknowledged: %+v", s)
	}
	e.svc.ProcessPending(ctx)
	hooks, _ := e.st.WebhooksOf(ctx, early.Enrollment.ID)
	if len(hooks) != 1 || hooks[0].Status != store.WebhookUnknownEnrollment {
		t.Fatalf("webhooks = %+v", hooks)
	}

	// The enrolment becomes known: the waiting event is applied.
	before := now.Add(-time.Second)
	initial := adapter.Enrollment{ID: early.Enrollment.ID, State: adapter.Initiated, CollegiateNumber: "282812345", UpdatedAt: &before}
	if _, err := e.st.UpsertEnrollment(ctx, p.ID, initial, []byte(`{"id":"dddddddd-dddd-4ddd-8ddd-dddddddddddd","state":"INITIATED"}`), true); err != nil {
		t.Fatal(err)
	}
	e.svc.ProcessPending(ctx)
	if got := e.state(t, early.Enrollment.ID); got.State != adapter.Expired {
		t.Fatalf("state = %s, want EXPIRED", got.State)
	}
}

func TestRefreshOnWebhookReadsTheSourceOfTruth(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()
	_, enr := e.enrol(t, "282812345")
	e.act(t, enr.ID, "obtain")

	calls, _ := e.st.CallsOf(ctx, enr.ID)
	if len(calls) != 2 || calls[0].Operation != "getEnrollment" || calls[0].Status != 200 {
		t.Fatalf("calls = %+v", calls)
	}
}

func TestEnrolValidation(t *testing.T) {
	e := newEnv(t, false)
	_, err := e.svc.Enrol(context.Background(), enrollment.NewPractitioner{FullName: "", AdministrativeNumber: "", CollegiateNumber: "12"})
	verr, ok := err.(*enrollment.ValidationError)
	if !ok || len(verr.Fields) != 3 {
		t.Fatalf("err = %v", err)
	}
}
