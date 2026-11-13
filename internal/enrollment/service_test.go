package enrollment_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/fikua/fikua-vitalia/internal/adapterstub"
	"github.com/fikua/fikua-vitalia/internal/cgcom"
	"github.com/fikua/fikua-vitalia/internal/directory"
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

	client := cgcom.NewClient(u, &http.Client{Timeout: 5 * time.Second}, cgcom.StaticTokenSource("tok"), st)
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
	if enr.State != cgcom.Initiated {
		t.Fatalf("state = %s", enr.State)
	}

	e.act(t, enr.ID, "mismatch")
	if got := e.state(t, enr.ID); got.State != cgcom.PendingAuthSources || *got.Decoded().AuthSourcesCause != "identity_mismatch" {
		t.Fatalf("after mismatch = %s", got.State)
	}

	e.act(t, enr.ID, "obtain")
	if got := e.state(t, enr.ID); got.State != cgcom.PendingConfirmation || got.Decoded().DoctorID == nil {
		t.Fatalf("after obtain = %s", got.State)
	}

	if err := e.svc.Decide(ctx, enr.ID, cgcom.Confirm); err != nil {
		t.Fatal(err)
	}
	if got := e.state(t, enr.ID); got.State != cgcom.Completed {
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
	if enr.State != cgcom.PendingConfirmation {
		t.Fatalf("state = %s", enr.State)
	}
	if err := e.svc.Decide(context.Background(), enr.ID, cgcom.Confirm); err != nil {
		t.Fatal(err)
	}
	firstProcedure := e.state(t, enr.ID).Decoded().DoctorID.ProcedureID

	e.act(t, enr.ID, "renew")
	got := e.state(t, enr.ID)
	if got.State != cgcom.Completed || got.InvalidatedReason != "renew" || got.InvalidatedProcedureID != firstProcedure {
		t.Fatalf("after renew = %s %q %q", got.State, got.InvalidatedReason, got.InvalidatedProcedureID)
	}

	e.act(t, enr.ID, "obtain") // the physician gets the renewed DoctorID
	got = e.state(t, enr.ID)
	if got.State != cgcom.PendingConfirmation || got.InvalidatedReason != "" {
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
	late := cgcom.Event{EventID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Event: cgcom.EventStateChanged, OccurredAt: older,
		Enrollment: cgcom.Enrollment{ID: enr.ID, State: cgcom.PendingAuthSources, CollegiateNumber: "282812345", AuthSourcesCause: &cause, UpdatedAt: &older}}
	fresh := cgcom.Event{EventID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", Event: cgcom.EventStateChanged, OccurredAt: newer,
		Enrollment: cgcom.Enrollment{ID: enr.ID, State: cgcom.Expired, CollegiateNumber: "282812345", UpdatedAt: &newer}}

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

	if got := e.state(t, enr.ID); got.State != cgcom.Expired {
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
	early := cgcom.Event{EventID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", Event: cgcom.EventStateChanged, OccurredAt: now,
		Enrollment: cgcom.Enrollment{ID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", State: cgcom.Expired, CollegiateNumber: "282812345", UpdatedAt: &now}}
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
	initial := cgcom.Enrollment{ID: early.Enrollment.ID, State: cgcom.Initiated, CollegiateNumber: "282812345", UpdatedAt: &before}
	if _, err := e.st.UpsertEnrollment(ctx, p.ID, initial, []byte(`{"id":"dddddddd-dddd-4ddd-8ddd-dddddddddddd","state":"INITIATED"}`), true); err != nil {
		t.Fatal(err)
	}
	e.svc.ProcessPending(ctx)
	if got := e.state(t, early.Enrollment.ID); got.State != cgcom.Expired {
		t.Fatalf("state = %s, want EXPIRED", got.State)
	}
}

func TestDirectoryEnrolmentIsAdoptedByRegistrationNumber(t *testing.T) {
	e := newEnv(t, false)
	e.svc.AdoptAfter = 0
	ctx := context.Background()
	known, err := e.st.FindOrCreatePractitioner(ctx, store.Practitioner{FullName: "Pau Vidal", AdministrativeNumber: "Y1234567X", CollegiateNumber: "282812345"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	send := func(id, coll string, state cgcom.State) {
		t.Helper()
		ev := cgcom.Event{EventID: id, Event: cgcom.EventStateChanged, OccurredAt: now,
			Enrollment: cgcom.Enrollment{ID: id, State: state, CollegiateNumber: coll, UpdatedAt: &now}}
		if s := e.stub.SendEvent(ctx, ev); s.Status != http.StatusOK {
			t.Fatalf("webhook: %+v", s)
		}
	}

	// A physician the clinic already has: the enrolment joins their record.
	send("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", "282812345", cgcom.Initiated)
	// One the clinic has never seen: a record is created from the enrolment.
	send("ffffffff-ffff-4fff-8fff-ffffffffffff", "282810010", cgcom.PendingConfirmation)
	e.svc.ProcessPending(ctx)

	if got := e.state(t, "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"); got.PractitionerID != known.ID || got.State != cgcom.Initiated {
		t.Fatalf("known physician: %+v", got)
	}
	created := e.state(t, "ffffffff-ffff-4fff-8fff-ffffffffffff")
	p, err := e.st.Practitioner(ctx, created.PractitionerID)
	if err != nil || p.CollegiateNumber != "282810010" || p.FullName != "Colegiado nº 282810010" {
		t.Fatalf("created physician: %+v %v", p, err)
	}
	hooks, _ := e.st.WebhooksOf(ctx, "ffffffff-ffff-4fff-8fff-ffffffffffff")
	if len(hooks) != 1 || hooks[0].Status != store.WebhookApplied {
		t.Fatalf("webhooks = %+v", hooks)
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

type fakeDirectory struct {
	got []string
	err error
}

func (d *fakeDirectory) EnsurePhysician(_ context.Context, p directory.Physician) error {
	d.got = append(d.got, p.CollegiateNumber+"|"+p.AdministrativeNumber+"|"+p.FullName)
	return d.err
}

func TestEnrolProvisionsTheDirectoryWithoutBlockingTheEnrolment(t *testing.T) {
	e := newEnv(t, false)
	dir := &fakeDirectory{}
	e.svc.Directory = dir
	p, enr := e.enrol(t, "282812345")
	if len(dir.got) != 1 || dir.got[0] != "282812345|12345678Z|Laia Puig Soler" || enr.State != cgcom.Initiated {
		t.Fatalf("directory got %v, enrolment %s", dir.got, enr.State)
	}

	// The directory is down: the enrolment still goes out, and HR is told.
	dir.err = errors.New("authentik unreachable")
	err := e.svc.EnrolAgain(context.Background(), p)
	var de *enrollment.DirectoryError
	if !errors.As(err, &de) {
		t.Fatalf("err = %v, want a DirectoryError", err)
	}
	if calls, _ := e.st.CallsOf(context.Background(), enr.ID); len(calls) == 0 {
		t.Fatal("the enrolment call was not made")
	}
}
