package doctorlogin

import (
	"context"
	"fmt"

	"github.com/fikua/fikua-vitalia/internal/cgcom"
	"github.com/fikua/fikua-vitalia/internal/store"
)

// Reasons a DoctorID login is refused.
const (
	ReasonNotRegistered    = "not_registered"       // the registration number is not a physician of the clinic
	ReasonNotVerified      = "not_verified"         // their enrolment is not COMPLETED
	ReasonInvalidated      = "doctorid_invalidated" // their DoctorID was revoked or is being renewed
	ReasonAmbiguous        = "ambiguous"            // more than one verified record with that number
	ReasonIdentityMismatch = "identity_mismatch"    // a different DoctorID identity than the one bound
	ReasonMissingClaim     = "missing_claim"        // no personal_administrative_number in the ID Token
	ReasonIdPError         = "idp_error"            // the IdP refused or the response was not valid
)

// Decision on a verified identity.
type Decision struct {
	Granted      bool
	Reason       string
	Practitioner store.Practitioner
	State        cgcom.State // of the practitioner's latest enrolment, when known
}

// Decide applies the clinic's rule: the registration number of the ID Token
// belongs to a physician whose enrolment is COMPLETED and whose DoctorID is
// not invalidated. The first login binds the DoctorID identity (iss, sub);
// later logins must present the same one.
func Decide(ctx context.Context, st *store.Store, id Identity) (Decision, error) {
	if id.CollegiateNumber == "" {
		return Decision{Reason: ReasonMissingClaim}, nil
	}
	rows, err := st.ListPractitioners(ctx)
	if err != nil {
		return Decision{}, err
	}
	var candidates, eligible []store.PractitionerRow
	for _, r := range rows {
		if r.CollegiateNumber != id.CollegiateNumber {
			continue
		}
		candidates = append(candidates, r)
		if r.Latest != nil && r.Latest.State == cgcom.Completed && r.Latest.InvalidatedReason == "" {
			eligible = append(eligible, r)
		}
	}
	switch {
	case len(candidates) == 0:
		return Decision{Reason: ReasonNotRegistered}, nil
	case len(eligible) > 1:
		return Decision{Reason: ReasonAmbiguous}, nil
	case len(eligible) == 0:
		d := Decision{Reason: ReasonNotVerified, Practitioner: candidates[0].Practitioner}
		if l := candidates[0].Latest; l != nil {
			d.State = l.State
			if l.InvalidatedReason != "" {
				d.Reason = ReasonInvalidated
			}
		}
		return d, nil
	}

	p := eligible[0]
	d := Decision{Practitioner: p.Practitioner, State: p.Latest.State}
	if p.DoctorIDSubject != "" && (p.DoctorIDSubject != id.Subject || p.DoctorIDIssuer != id.Issuer) {
		d.Reason = ReasonIdentityMismatch
		return d, nil
	}
	if p.DoctorIDSubject == "" {
		if err := st.BindDoctorID(ctx, p.ID, id.Issuer, id.Subject); err != nil {
			return Decision{}, fmt.Errorf("bind DoctorID: %w", err)
		}
	}
	d.Granted = true
	return d, nil
}
