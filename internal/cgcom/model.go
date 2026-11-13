package cgcom

// Contract types of the enrolment API.

import (
	"encoding/json"
	"regexp"
	"strings"
	"time"
)

// State of an enrolment, as the adapter reports it.
type State string

const (
	Initiated           State = "INITIATED"
	PendingAuthSources  State = "PENDING_AUTH_SOURCES"
	PendingConfirmation State = "PENDING_CONFIRMATION"
	Completed           State = "COMPLETED"
	RejectedByRegistry  State = "REJECTED_BY_REGISTRY"
	Expired             State = "EXPIRED"
	Cancelled           State = "CANCELLED"
)

// Final states never change again: the platform enrols anew.
func (s State) Final() bool {
	return s == RejectedByRegistry || s == Expired || s == Cancelled
}

// CanDecide reports whether confirm/reject is allowed.
func (s State) CanDecide() bool { return s == PendingConfirmation }

// CanCancel reports whether cancellation is allowed.
func (s State) CanCancel() bool {
	return s == Initiated || s == PendingAuthSources || s == PendingConfirmation
}

// Enrollment is the body of the create and read responses and of the webhook.
type Enrollment struct {
	ID                string     `json:"id"`
	State             State      `json:"state"`
	CollegiateNumber  string     `json:"collegiate_number"`
	AuthSourcesCause  *string    `json:"auth_sources_cause,omitempty"`
	IssuancePortalURL *string    `json:"issuance_portal_url,omitempty"`
	DoctorID          *DoctorID  `json:"doctorid,omitempty"`
	ExpiresAt         *time.Time `json:"expires_at,omitempty"`
	UpdatedAt         *time.Time `json:"updated_at,omitempty"`
}

// DoctorID is the credential summary the adapter returns.
type DoctorID struct {
	ProcedureID string         `json:"procedure_id"`
	ValidFrom   *time.Time     `json:"valid_from,omitempty"`
	ValidUntil  *time.Time     `json:"valid_until,omitempty"`
	Data        map[string]any `json:"data"`
}

// Webhook event names.
const (
	EventStateChanged       = "enrollment_state_changed"
	EventDoctorIDInvalidate = "doctorid_invalidated"
)

// Event is the webhook body.
type Event struct {
	EventID    string     `json:"event_id"`
	Event      string     `json:"event"`
	OccurredAt time.Time  `json:"occurred_at"`
	Reason     string     `json:"reason,omitempty"`
	Enrollment Enrollment `json:"enrollment"`
}

// Problem is an RFC 9457 problem details body.
type Problem struct {
	Type       string      `json:"type"`
	Title      string      `json:"title"`
	Status     int         `json:"status"`
	Detail     string      `json:"detail"`
	Instance   string      `json:"instance,omitempty"`
	Violations []Violation `json:"violations,omitempty"`
}

// Violation is one field error of an invalid_request problem.
type Violation struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

var (
	uuidRE       = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	collegiateRE = regexp.MustCompile(`^[0-9]{9}$`)
	adminRE      = regexp.MustCompile(`^[A-Z0-9]{1,20}$`)
)

// ValidID reports whether id is a UUID, the only form the contract allows.
func ValidID(id string) bool { return uuidRE.MatchString(id) }

// NormaliseAdministrativeNumber applies the contract rule: upper case, no
// spaces or hyphens.
func NormaliseAdministrativeNumber(s string) string {
	s = strings.ToUpper(s)
	return strings.NewReplacer(" ", "", "-", "", "\t", "").Replace(s)
}

// ValidAdministrativeNumber checks a normalised DNI, NIE or passport number.
func ValidAdministrativeNumber(s string) bool { return adminRE.MatchString(s) }

// ValidCollegiateNumber checks the 9-digit CGCOM registration number.
func ValidCollegiateNumber(s string) bool { return collegiateRE.MatchString(s) }

// DecodeEnrollment parses an enrolment body.
func DecodeEnrollment(raw []byte) (Enrollment, error) {
	var e Enrollment
	err := json.Unmarshal(raw, &e)
	return e, err
}
