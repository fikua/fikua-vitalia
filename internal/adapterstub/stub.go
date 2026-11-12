// Package adapterstub is an in-memory stand-in for the enrolment API,
// written from the contract only. It serves the tests and the local
// simulator (cmd/fakeadapter), where it also plays the physician and the
// registry: it moves enrolments and sends signed webhooks.
//
// Scenarios, chosen by the registration number:
//   - ends in 0: the physician already has a DoctorID (201 PENDING_CONFIRMATION)
//   - starts with 999: the issuer is down (503 issuer_unavailable, Retry-After 30)
//   - anything else: 201 INITIATED with the issuance portal address
package adapterstub

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/fikua/fikua-vitalia/internal/adapter"
	"github.com/fikua/fikua-vitalia/internal/idpstub"
	"github.com/fikua/fikua-vitalia/internal/webhook"
)

// Stub is the fake adapter.
type Stub struct {
	Token         string // bearer token the platform must send; empty accepts any
	PortalURL     string
	WebhookURL    string
	WebhookSecret []byte
	HTTP          *http.Client
	Now           func() time.Time

	mu   sync.Mutex
	recs map[string]*record
	ord  []string
}

type record struct {
	e     adapter.Enrollment
	admin string
}

// Sent is the outcome of a webhook the stub sent.
type Sent struct {
	Status int
	Body   string
	Err    error
}

func (s *Stub) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// Handler serves the enrolment API.
func (s *Stub) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/enrollments", s.auth(s.create))
	mux.HandleFunc("GET /api/v1/enrollments/{id}", s.auth(s.get))
	mux.HandleFunc("POST /api/v1/enrollments/{id}/confirmation", s.auth(s.confirm))
	mux.HandleFunc("POST /api/v1/enrollments/{id}/cancellation", s.auth(s.cancel))
	return mux
}

func (s *Stub) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		if h == "" {
			problem(w, http.StatusUnauthorized, "authentication_required", "No access token.", nil)
			return
		}
		if s.Token != "" && h != "Bearer "+s.Token {
			problem(w, http.StatusUnauthorized, "invalid_token", "The access token is not valid.", nil)
			return
		}
		next(w, r)
	}
}

func (s *Stub) create(w http.ResponseWriter, r *http.Request) {
	var in struct {
		AdministrativeNumber string `json:"administrative_number"`
		CollegiateNumber     string `json:"collegiate_number"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		problem(w, http.StatusBadRequest, "invalid_request", "The body is not valid.", nil)
		return
	}
	var v []adapter.Violation
	admin := adapter.NormaliseAdministrativeNumber(in.AdministrativeNumber)
	if !adapter.ValidAdministrativeNumber(admin) {
		v = append(v, adapter.Violation{Field: "administrative_number", Message: "required, at most 20 characters"})
	}
	if !adapter.ValidCollegiateNumber(in.CollegiateNumber) {
		v = append(v, adapter.Violation{Field: "collegiate_number", Message: "must be 9 digits"})
	}
	if len(v) > 0 {
		problem(w, http.StatusBadRequest, "invalid_request", "Missing field or wrong format.", v)
		return
	}
	if strings.HasPrefix(in.CollegiateNumber, "999") {
		w.Header().Set("Retry-After", "30")
		problem(w, http.StatusServiceUnavailable, "issuer_unavailable", "The issuer did not answer. Nothing was opened.", nil)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range s.ord {
		rec := s.recs[id]
		if rec.admin == admin && rec.e.CollegiateNumber == in.CollegiateNumber && !rec.e.State.Final() {
			writeJSON(w, http.StatusOK, rec.e)
			return
		}
	}
	now := s.now()
	exp := now.Add(7 * 24 * time.Hour)
	e := adapter.Enrollment{ID: newUUID(), CollegiateNumber: in.CollegiateNumber, ExpiresAt: &exp, UpdatedAt: &now}
	if strings.HasSuffix(in.CollegiateNumber, "0") {
		e.State = adapter.PendingConfirmation
		e.DoctorID = s.doctorID(in.CollegiateNumber, now)
	} else {
		e.State = adapter.Initiated
		e.IssuancePortalURL = &s.PortalURL
	}
	if s.recs == nil {
		s.recs = map[string]*record{}
	}
	s.recs[e.ID] = &record{e: e, admin: admin}
	s.ord = append(s.ord, e.ID)
	writeJSON(w, http.StatusCreated, e)
}

func (s *Stub) get(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.recs[r.PathValue("id")]
	if !ok {
		problem(w, http.StatusNotFound, "enrollment_not_found", "No such enrollment.", nil)
		return
	}
	writeJSON(w, http.StatusOK, rec.e)
}

func (s *Stub) confirm(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Decision    string `json:"decision"`
		Attestation string `json:"attestation"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil || (in.Decision != "confirm" && in.Decision != "reject") {
		problem(w, http.StatusBadRequest, "invalid_request", "decision must be confirm or reject.",
			[]adapter.Violation{{Field: "decision", Message: "confirm or reject"}})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.recs[r.PathValue("id")]
	if !ok {
		problem(w, http.StatusNotFound, "enrollment_not_found", "No such enrollment.", nil)
		return
	}
	target := adapter.Completed
	if in.Decision == "reject" {
		target = adapter.Cancelled
	}
	switch rec.e.State {
	case adapter.PendingConfirmation:
		s.move(rec, target)
		if target == adapter.Cancelled {
			rec.e.DoctorID = nil
		}
	case target: // same decision again: idempotent
	default:
		problem(w, http.StatusConflict, "enrollment_state_conflict",
			fmt.Sprintf("Cannot %s an enrollment in state %s.", in.Decision, rec.e.State), nil)
		return
	}
	writeJSON(w, http.StatusOK, rec.e)
}

func (s *Stub) cancel(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.recs[r.PathValue("id")]
	if !ok {
		problem(w, http.StatusNotFound, "enrollment_not_found", "No such enrollment.", nil)
		return
	}
	switch {
	case rec.e.State == adapter.Cancelled:
	case rec.e.State.CanCancel():
		s.move(rec, adapter.Cancelled)
		rec.e.DoctorID, rec.e.IssuancePortalURL, rec.e.AuthSourcesCause = nil, nil, nil
	default:
		problem(w, http.StatusConflict, "enrollment_state_conflict",
			fmt.Sprintf("Cannot cancel an enrollment in state %s.", rec.e.State), nil)
		return
	}
	writeJSON(w, http.StatusOK, rec.e)
}

func (s *Stub) move(rec *record, to adapter.State) {
	now := s.now()
	rec.e.State = to
	rec.e.UpdatedAt = &now
}

// ------------------------------------------------------------ simulator actions

// Actions the simulator can run on an enrolment.
var Actions = []string{"obtain", "mismatch", "dispute", "reject-registry", "expire", "revoke", "renew"}

// ErrNoEnrollment and ErrNotAllowed are returned by Act.
var (
	ErrNoEnrollment = errors.New("no such enrollment")
	ErrNotAllowed   = errors.New("action not allowed in this state")
)

// ActOptions refine an action: the registry name for "obtain".
type ActOptions struct{ GivenName, FamilyName string }

// Act moves an enrolment as the physician, the registry or the clock would,
// and sends the webhook the contract says.
func (s *Stub) Act(ctx context.Context, id, action string) (Sent, error) {
	return s.ActWith(ctx, id, action, ActOptions{})
}

// ActWith is Act with options.
func (s *Stub) ActWith(ctx context.Context, id, action string, opt ActOptions) (Sent, error) {
	s.mu.Lock()
	rec, ok := s.recs[id]
	if !ok {
		s.mu.Unlock()
		return Sent{}, ErrNoEnrollment
	}
	st := rec.e.State
	event, reason := adapter.EventStateChanged, ""
	switch action {
	case "obtain": // the physician obtains a (new) DoctorID
		if st != adapter.Initiated && st != adapter.PendingAuthSources && st != adapter.Completed {
			s.mu.Unlock()
			return Sent{}, ErrNotAllowed
		}
		s.move(rec, adapter.PendingConfirmation)
		rec.e.DoctorID = s.doctorID(rec.e.CollegiateNumber, s.now())
		if opt.GivenName != "" {
			rec.e.DoctorID.Data["givenName"] = strings.ToUpper(strings.TrimSpace(opt.GivenName))
		}
		if opt.FamilyName != "" {
			rec.e.DoctorID.Data["familyName"] = strings.ToUpper(strings.TrimSpace(opt.FamilyName))
		}
		rec.e.IssuancePortalURL, rec.e.AuthSourcesCause = nil, nil
	case "mismatch", "dispute":
		if st != adapter.Initiated && st != adapter.PendingAuthSources {
			s.mu.Unlock()
			return Sent{}, ErrNotAllowed
		}
		cause := "identity_mismatch"
		if action == "dispute" {
			cause = "holder_dispute"
		}
		s.move(rec, adapter.PendingAuthSources)
		rec.e.AuthSourcesCause = &cause
	case "reject-registry":
		if st != adapter.Initiated && st != adapter.PendingAuthSources {
			s.mu.Unlock()
			return Sent{}, ErrNotAllowed
		}
		s.move(rec, adapter.RejectedByRegistry)
		rec.e.IssuancePortalURL, rec.e.AuthSourcesCause = nil, nil
	case "expire":
		if st.Final() || st == adapter.Completed {
			s.mu.Unlock()
			return Sent{}, ErrNotAllowed
		}
		s.move(rec, adapter.Expired)
		rec.e.IssuancePortalURL, rec.e.AuthSourcesCause, rec.e.DoctorID = nil, nil, nil
	case "revoke", "renew":
		if st != adapter.PendingConfirmation && st != adapter.Completed {
			s.mu.Unlock()
			return Sent{}, ErrNotAllowed
		}
		event, reason = adapter.EventDoctorIDInvalidate, action
		now := s.now()
		rec.e.UpdatedAt = &now
	default:
		s.mu.Unlock()
		return Sent{}, fmt.Errorf("unknown action %q", action)
	}
	ev := adapter.Event{EventID: newUUID(), Event: event, OccurredAt: s.now(), Reason: reason, Enrollment: rec.e}
	s.mu.Unlock()
	return s.SendEvent(ctx, ev), nil
}

// SendEvent signs and posts ev to the platform's webhook.
func (s *Stub) SendEvent(ctx context.Context, ev adapter.Event) Sent {
	if s.WebhookURL == "" {
		return Sent{Err: errors.New("no webhook URL configured")}
	}
	body, _ := json.Marshal(ev)
	client := s.HTTP
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	status, resp, err := webhook.Send(ctx, client, s.WebhookURL, s.WebhookSecret, body, time.Now())
	return Sent{Status: status, Body: resp, Err: err}
}

// Snapshot returns the enrolments, newest first.
func (s *Stub) Snapshot() []adapter.Enrollment {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]adapter.Enrollment, 0, len(s.ord))
	for i := len(s.ord) - 1; i >= 0; i-- {
		out = append(out, s.recs[s.ord[i]].e)
	}
	return out
}

// ------------------------------------------------------------------ helpers

var givenNames = []string{"JOSE ANTONIO", "MARIA", "LAIA", "JAVIER", "CARMEN", "PAU", "LUCIA", "ANDRES"}
var familyNames = []string{"GARCIA FERNANDEZ", "PUIG SOLER", "MARTIN LOPEZ", "RUIZ NAVARRO", "VIDAL COSTA", "SANZ MORENO"}
var boards = []string{"Colegio Oficial de Médicos de Madrid", "Col·legi Oficial de Metges de Barcelona", "Colegio Oficial de Médicos de Valencia"}
var specialities = []string{"Cardiología", "Medicina Familiar y Comunitaria", "Pediatría", "Dermatología", "Traumatología"}

// doctorID builds synthetic DoctorID data, stable for a registration number.
func (s *Stub) doctorID(coll string, now time.Time) *adapter.DoctorID {
	n := 0
	for _, c := range coll {
		n += int(c - '0')
	}
	until := now.AddDate(5, 0, 0)
	return &adapter.DoctorID{
		ProcedureID: newUUID(),
		ValidFrom:   &now,
		ValidUntil:  &until,
		Data: map[string]any{
			"givenName":                      givenNames[n%len(givenNames)],
			"familyName":                     familyNames[n%len(familyNames)],
			"personal_administrative_number": coll,
			"medical_board":                  []string{boards[n%len(boards)]},
			"medical_speciality":             []string{specialities[n%len(specialities)]},
			"legally_entitled":               true,
		},
	}
}

func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func problem(w http.ResponseWriter, status int, typ, detail string, v []adapter.Violation) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(adapter.Problem{
		Type: typ, Title: http.StatusText(status), Status: status, Detail: detail, Instance: "/", Violations: v,
	})
}

// Holders returns one wallet entry per registration number that has a
// DoctorID in the stub (enrolments in PENDING_CONFIRMATION or COMPLETED).
func (s *Stub) Holders() []idpstub.Holder {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := map[string]bool{}
	var out []idpstub.Holder
	for i := len(s.ord) - 1; i >= 0; i-- {
		e := s.recs[s.ord[i]].e
		if e.DoctorID == nil || seen[e.CollegiateNumber] {
			continue
		}
		seen[e.CollegiateNumber] = true
		d := e.DoctorID.Data
		given, _ := d["givenName"].(string)
		family, _ := d["familyName"].(string)
		out = append(out, idpstub.Holder{CollegiateNumber: e.CollegiateNumber, GivenName: given, FamilyName: family,
			Data: d, Note: "inscripción " + string(e.State)})
	}
	return out
}
