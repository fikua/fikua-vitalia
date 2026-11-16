// Package audit emits the audit events of Clínica Vitalia and counts its
// business operations (Fikua observability convention, OBS-09 and OBS-12).
//
// An audit event is an OpenTelemetry log record with event.domain = audit, a
// name from the catalogue below and only the attributes it lists. The platform
// Collector archives it for five years in a locked bucket, where it cannot be
// corrected: an event or attribute is added here only after the catalogue has
// been reviewed (2026-11-16, Oriol Canadés).
//
//	event.name                  when                                              attributes
//	practitioner.registered     HR registered a physician                         practitioner.id
//	enrollment.requested        the enrolment was sent to the enrolment API        practitioner.id, enrollment.id
//	enrollment.decided          HR confirmed or rejected the DoctorID data         practitioner.id, enrollment.id, decision
//	enrollment.cancelled        HR cancelled the enrolment                        practitioner.id, enrollment.id
//	enrollment.status_changed   a webhook or a refresh moved the enrolment state   enrollment.id, status
//	doctorid.unbound            HR unbound the DoctorID of a physician             practitioner.id
//	professional.signed_in      a physician entered with DoctorID                  practitioner.id
//	auth.rejected               an access was refused                             area (profesional | gestion), reason
//	webhook.rejected            a webhook had a missing or wrong signature         reason
//
// Never a name, a national ID, a registration number, an e-mail address or an
// IP address: only internal identifiers. Events are emitted after the action is
// committed, and emission never fails the caller.
package audit

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/metric"
)

const scope = "fikua-vitalia/audit"

// Emit sends one audit event. attrs must be those of the catalogue.
func Emit(ctx context.Context, name string, attrs ...attribute.KeyValue) {
	var r log.Record
	r.SetSeverity(log.SeverityInfo)
	r.SetSeverityText("INFO")
	r.SetBody(attribute.StringValue(name))
	r.AddAttributes(attribute.String("event.domain", "audit"), attribute.String("event.name", name))
	r.AddAttributes(attrs...)
	global.GetLoggerProvider().Logger(scope).Emit(ctx, r)
}

func PractitionerRegistered(ctx context.Context, practitionerID int64) {
	Emit(ctx, "practitioner.registered", attribute.Int64("practitioner.id", practitionerID))
	Count(ctx, "practitioner.register", "success", "")
}

func EnrollmentRequested(ctx context.Context, practitionerID int64, enrollmentID string) {
	Emit(ctx, "enrollment.requested",
		attribute.Int64("practitioner.id", practitionerID), attribute.String("enrollment.id", enrollmentID))
	Count(ctx, "enrollment.request", "success", "")
}

// EnrollmentDecided records decision "confirmed" or "rejected".
func EnrollmentDecided(ctx context.Context, practitionerID int64, enrollmentID, decision string) {
	Emit(ctx, "enrollment.decided",
		attribute.Int64("practitioner.id", practitionerID), attribute.String("enrollment.id", enrollmentID),
		attribute.String("decision", decision))
	Count(ctx, "enrollment.decide", decision, "")
}

func EnrollmentCancelled(ctx context.Context, practitionerID int64, enrollmentID string) {
	Emit(ctx, "enrollment.cancelled",
		attribute.Int64("practitioner.id", practitionerID), attribute.String("enrollment.id", enrollmentID))
	Count(ctx, "enrollment.cancel", "success", "")
}

func EnrollmentStatusChanged(ctx context.Context, enrollmentID, status string) {
	Emit(ctx, "enrollment.status_changed",
		attribute.String("enrollment.id", enrollmentID), attribute.String("status", status))
}

func DoctorIDUnbound(ctx context.Context, practitionerID int64) {
	Emit(ctx, "doctorid.unbound", attribute.Int64("practitioner.id", practitionerID))
}

func ProfessionalSignedIn(ctx context.Context, practitionerID int64) {
	Emit(ctx, "professional.signed_in", attribute.Int64("practitioner.id", practitionerID))
	Count(ctx, "professional.sign_in", "success", "")
}

// AuthRejected records a refused access; area is "profesional" or "gestion"
// and reason a stable code (doctorlogin.Reason*, invalid_credentials, not_staff).
func AuthRejected(ctx context.Context, area, reason string) {
	Emit(ctx, "auth.rejected", attribute.String("area", area), attribute.String("reason", reason))
	op := "professional.sign_in"
	if area == "gestion" {
		op = "staff.sign_in"
	}
	Count(ctx, op, "rejected", reason)
}

func WebhookRejected(ctx context.Context, reason string) {
	Emit(ctx, "webhook.rejected", attribute.String("reason", reason))
	Count(ctx, "webhook.receive", "rejected", reason)
}

var (
	counterOnce sync.Once
	counter     metric.Int64Counter
)

// Count adds one business operation to vitalia.business.operations (OBS-09).
// errorType is set only when the operation failed or was refused.
func Count(ctx context.Context, operation, outcome, errorType string) {
	counterOnce.Do(func() {
		counter, _ = otel.GetMeterProvider().Meter(scope).Int64Counter("vitalia.business.operations",
			metric.WithDescription("Business operations of Clínica Vitalia, by operation and outcome"),
			metric.WithUnit("{operation}"))
	})
	if counter == nil {
		return
	}
	attrs := []attribute.KeyValue{attribute.String("operation", operation), attribute.String("outcome", outcome)}
	if errorType != "" {
		attrs = append(attrs, attribute.String("error.type", errorType))
	}
	counter.Add(ctx, 1, metric.WithAttributes(attrs...))
}
