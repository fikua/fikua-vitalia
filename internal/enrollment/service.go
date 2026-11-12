// Package enrollment is what the clinic does with the enrolment API: enrol
// its physicians, keep their state in step with the adapter and decide on
// their DoctorID data.
package enrollment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/fikua/fikua-vitalia/internal/adapter"
	"github.com/fikua/fikua-vitalia/internal/store"
)

// Service orchestrates the store and the adapter client.
type Service struct {
	store            *store.Store
	client           *adapter.Client
	logger           *slog.Logger
	refreshOnWebhook bool
	wake             chan struct{}

	// AdoptAfter is how long an event for an enrolment the clinic did not
	// open waits before the clinic adopts it by registration number. Those
	// enrolments come from the clinic's directory (SCIM). The wait lets a
	// webhook that overtook our own POST response find that response first.
	AdoptAfter time.Duration
	Now        func() time.Time
}

// DefaultAdoptAfter is the default AdoptAfter.
const DefaultAdoptAfter = 15 * time.Second

// New builds the service.
func New(st *store.Store, client *adapter.Client, logger *slog.Logger, refreshOnWebhook bool) *Service {
	return &Service{store: st, client: client, logger: logger, refreshOnWebhook: refreshOnWebhook, wake: make(chan struct{}, 1),
		AdoptAfter: DefaultAdoptAfter, Now: time.Now}
}

// ValidationError is a form error shown to the operator.
type ValidationError struct{ Fields map[string]string }

func (e *ValidationError) Error() string { return "invalid input" }

// NewPractitioner is the clinic's own record of a physician.
type NewPractitioner struct {
	FullName             string
	AdministrativeNumber string
	CollegiateNumber     string
	Specialty            string
	Email                string
}

// Enrol registers the physician (or finds them) and enrols them. It returns
// the practitioner even when the adapter call fails, so the operator can
// retry from their page.
func (s *Service) Enrol(ctx context.Context, in NewPractitioner) (store.Practitioner, error) {
	in.FullName = strings.TrimSpace(in.FullName)
	in.AdministrativeNumber = adapter.NormaliseAdministrativeNumber(in.AdministrativeNumber)
	in.CollegiateNumber = strings.TrimSpace(in.CollegiateNumber)
	in.Specialty = strings.TrimSpace(in.Specialty)
	in.Email = strings.TrimSpace(in.Email)

	fields := map[string]string{}
	if in.FullName == "" {
		fields["full_name"] = "Indica el nombre y apellidos."
	}
	if !adapter.ValidAdministrativeNumber(in.AdministrativeNumber) {
		fields["administrative_number"] = "DNI, NIE o pasaporte: letras y números, hasta 20."
	}
	if !adapter.ValidCollegiateNumber(in.CollegiateNumber) {
		fields["collegiate_number"] = "El número de colegiado tiene 9 dígitos."
	}
	if len(fields) > 0 {
		return store.Practitioner{}, &ValidationError{Fields: fields}
	}

	p, err := s.store.FindOrCreatePractitioner(ctx, store.Practitioner{
		FullName: in.FullName, AdministrativeNumber: in.AdministrativeNumber, CollegiateNumber: in.CollegiateNumber,
		Specialty: in.Specialty, Email: in.Email,
	})
	if err != nil {
		return store.Practitioner{}, err
	}
	return p, s.EnrolAgain(ctx, p)
}

// EnrolAgain asks the adapter to enrol an existing practitioner: after a
// final state, or when the first attempt failed.
func (s *Service) EnrolAgain(ctx context.Context, p store.Practitioner) error {
	res, err := s.client.CreateEnrollment(ctx, p.AdministrativeNumber, p.CollegiateNumber)
	if err != nil {
		return err
	}
	if _, err := s.store.UpsertEnrollment(ctx, p.ID, res.Enrollment, res.Raw, true); err != nil {
		return fmt.Errorf("store enrollment: %w", err)
	}
	// A webhook may have arrived before this response: let the processor
	// pick up any event that was waiting for this enrolment.
	s.Wake()
	return nil
}

// Refresh reads the enrolment from the adapter: the source of truth.
func (s *Service) Refresh(ctx context.Context, id string) error {
	res, err := s.client.GetEnrollment(ctx, id)
	if err != nil {
		return err
	}
	_, err = s.store.UpsertEnrollment(ctx, 0, res.Enrollment, res.Raw, true)
	return err
}

// Decide confirms or rejects the physician's DoctorID data.
func (s *Service) Decide(ctx context.Context, id string, d adapter.Decision) error {
	res, err := s.client.Decide(ctx, id, d)
	if err != nil {
		return err
	}
	_, err = s.store.UpsertEnrollment(ctx, 0, res.Enrollment, res.Raw, true)
	return err
}

// Cancel cancels the enrolment.
func (s *Service) Cancel(ctx context.Context, id string) error {
	res, err := s.client.Cancel(ctx, id)
	if err != nil {
		return err
	}
	_, err = s.store.UpsertEnrollment(ctx, 0, res.Enrollment, res.Raw, true)
	return err
}

// Wake asks the processor to run now. It never blocks.
func (s *Service) Wake() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Run processes stored webhooks until ctx is done: on every Wake and, as a
// safety net, every interval.
func (s *Service) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		s.ProcessPending(ctx)
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
		case <-ticker.C:
		}
	}
}

// ProcessPending applies every stored event still to be processed.
func (s *Service) ProcessPending(ctx context.Context) {
	events, err := s.store.WebhooksToProcess(ctx, 100)
	if err != nil {
		s.logger.Error("list webhooks to process", "err", err)
		return
	}
	for _, ev := range events {
		status, detail, refresh := s.apply(ctx, ev)
		if ev.Status == store.WebhookUnknownEnrollment && status == store.WebhookUnknownEnrollment {
			continue // still unknown: leave it as it was
		}
		if err := s.store.SetWebhookStatus(ctx, ev.ID, status, detail); err != nil {
			s.logger.Error("set webhook status", "err", err, "event_id", ev.EventID)
			continue
		}
		if refresh && s.refreshOnWebhook {
			if err := s.Refresh(ctx, ev.EnrollmentID); err != nil {
				s.logger.Warn("refresh after webhook failed", "err", err, "enrollment_id", ev.EnrollmentID)
			}
		}
	}
}

func (s *Service) apply(ctx context.Context, rec store.WebhookEvent) (status, detail string, refresh bool) {
	var ev adapter.Event
	if err := json.Unmarshal([]byte(rec.RawBody), &ev); err != nil {
		return store.WebhookError, "body is not valid JSON: " + err.Error(), false
	}
	if ev.Event != adapter.EventStateChanged && ev.Event != adapter.EventDoctorIDInvalidate {
		return store.WebhookIgnored, fmt.Sprintf("unknown event %q", ev.Event), false
	}

	stored, err := s.store.Enrollment(ctx, ev.Enrollment.ID)
	adopted := ""
	if errors.Is(err, store.ErrNotFound) {
		if s.Now().Sub(rec.ReceivedAt) < s.AdoptAfter {
			return store.WebhookUnknownEnrollment, "no enrollment with this id (yet)", false
		}
		if adopted, err = s.adopt(ctx, ev.Enrollment); err != nil {
			return store.WebhookError, err.Error(), false
		}
		if adopted == "" {
			return store.WebhookUnknownEnrollment, "no enrollment with this id, and more than one physician with its registration number", false
		}
		stored, err = s.store.Enrollment(ctx, ev.Enrollment.ID)
	}
	if err != nil {
		return store.WebhookError, err.Error(), false
	}

	raw, _ := json.Marshal(ev.Enrollment)
	outcome, err := s.store.UpsertEnrollment(ctx, 0, ev.Enrollment, raw, false)
	if err != nil {
		return store.WebhookError, err.Error(), false
	}

	if ev.Event == adapter.EventDoctorIDInvalidate {
		procedure := ""
		if ev.Enrollment.DoctorID != nil {
			procedure = ev.Enrollment.DoctorID.ProcedureID
		}
		// A late notice about a DoctorID the enrolment no longer holds must
		// not flag the newer one.
		if current := stored.Decoded().DoctorID; outcome == store.Stale && current != nil && procedure != "" && current.ProcedureID != procedure {
			return store.WebhookStale, "invalidation of an older DoctorID " + procedure, true
		}
		at := ev.OccurredAt
		if at.IsZero() {
			at = time.Now()
		}
		if err := s.store.MarkInvalidated(ctx, ev.Enrollment.ID, ev.Reason, procedure, at); err != nil {
			return store.WebhookError, err.Error(), false
		}
		return store.WebhookApplied, "DoctorID invalidated: " + ev.Reason, true
	}

	if outcome == store.Stale {
		return store.WebhookStale, "older than the stored state; not applied", true
	}
	return store.WebhookApplied, adopted + "state " + string(ev.Enrollment.State), true
}

// adopt stores an enrolment the clinic did not open (its directory
// provisioned the physician by SCIM) under the physician with its
// registration number, creating the physician when there is none. It
// returns a note for the event detail, or "" when the number is ambiguous.
func (s *Service) adopt(ctx context.Context, e adapter.Enrollment) (string, error) {
	rows, err := s.store.ListPractitioners(ctx)
	if err != nil {
		return "", err
	}
	var matches []store.Practitioner
	for _, r := range rows {
		if r.CollegiateNumber == e.CollegiateNumber {
			matches = append(matches, r.Practitioner)
		}
	}
	note := "adopted by registration number; "
	var p store.Practitioner
	switch len(matches) {
	case 0:
		if !adapter.ValidCollegiateNumber(e.CollegiateNumber) {
			return "", fmt.Errorf("enrolment without a valid registration number")
		}
		// The directory, not the clinic, holds the name and the DNI: use
		// what the DoctorID says, when there is one.
		name, specialty := "Colegiado nº "+e.CollegiateNumber, ""
		if e.DoctorID != nil {
			given, _ := e.DoctorID.Data["givenName"].(string)
			family, _ := e.DoctorID.Data["familyName"].(string)
			if n := strings.TrimSpace(given + " " + family); n != "" {
				name = n
			}
			if sp, ok := e.DoctorID.Data["medical_speciality"].([]any); ok && len(sp) > 0 {
				specialty, _ = sp[0].(string)
			}
		}
		if p, err = s.store.FindOrCreatePractitioner(ctx, store.Practitioner{
			FullName: name, CollegiateNumber: e.CollegiateNumber, Specialty: specialty}); err != nil {
			return "", err
		}
		note = "physician created from the directory's enrolment; "
	case 1:
		p = matches[0]
	default:
		return "", nil
	}
	raw, _ := json.Marshal(e)
	if _, err := s.store.UpsertEnrollment(ctx, p.ID, e, raw, false); err != nil {
		return "", fmt.Errorf("store adopted enrollment: %w", err)
	}
	s.logger.Info("enrolment adopted", "enrollment_id", e.ID, "practitioner_id", p.ID)
	return note, nil
}
