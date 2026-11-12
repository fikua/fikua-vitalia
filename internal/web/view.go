package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"

	"golang.org/x/text/unicode/norm"

	"github.com/fikua/fikua-vitalia/internal/adapter"
	"github.com/fikua/fikua-vitalia/internal/store"
)

func stateLabel(s adapter.State) string {
	switch s {
	case adapter.Initiated:
		return "Esperando al médico"
	case adapter.PendingAuthSources:
		return "Datos colegiales por corregir"
	case adapter.PendingConfirmation:
		return "Pendiente de nuestra revisión"
	case adapter.Completed:
		return "Verificado"
	case adapter.RejectedByRegistry:
		return "Rechazado por el registro colegial"
	case adapter.Expired:
		return "Caducado"
	case adapter.Cancelled:
		return "Cancelado"
	}
	return string(s)
}

func stateTone(s adapter.State) string {
	switch s {
	case adapter.Completed:
		return "ok"
	case adapter.PendingConfirmation:
		return "action"
	case adapter.Initiated:
		return "wait"
	case adapter.PendingAuthSources:
		return "warn"
	}
	return "off"
}

func causeLabel(c *string) string {
	if c == nil {
		return ""
	}
	switch *c {
	case "identity_mismatch":
		return "Los datos del registro colegial no coinciden con los de su certificado."
	case "holder_dispute":
		return "El propio médico ha indicado que sus datos colegiales no son correctos."
	}
	return *c
}

func eventLabel(e string) string {
	switch e {
	case adapter.EventStateChanged:
		return "Cambio de estado"
	case adapter.EventDoctorIDInvalidate:
		return "DoctorID invalidado"
	case "":
		return "—"
	}
	return e
}

func webhookTone(status string) string {
	switch status {
	case store.WebhookApplied:
		return "ok"
	case store.WebhookPending, store.WebhookStale:
		return "wait"
	case store.WebhookUnknownEnrollment, store.WebhookIgnored:
		return "warn"
	}
	return "bad"
}

func (s *Server) fmtTime(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.In(s.loc).Format("02/01/2006 15:04:05")
}

func (s *Server) fmtTimePtr(t *time.Time) string {
	if t == nil {
		return "—"
	}
	return s.fmtTime(*t)
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func prettyJSON(raw string) string {
	var buf bytes.Buffer
	if err := json.Indent(&buf, []byte(raw), "", "  "); err != nil {
		return raw
	}
	return buf.String()
}

// dataValue renders a DoctorID claim: arrays as a comma list.
func dataValue(v any) string {
	switch x := v.(type) {
	case nil:
		return "—"
	case []any:
		parts := make([]string, 0, len(x))
		for _, p := range x {
			parts = append(parts, fmt.Sprint(p))
		}
		return strings.Join(parts, ", ")
	case bool:
		if x {
			return "Sí"
		}
		return "No"
	}
	return fmt.Sprint(v)
}

// compare puts the clinic's record next to the DoctorID data so the operator
// can decide. The name comparison ignores case, accents and extra spaces.
func compare(p store.Practitioner, e adapter.Enrollment) []check {
	if e.DoctorID == nil {
		return nil
	}
	d := e.DoctorID.Data
	str := func(k string) string { return strings.TrimSpace(dataValue(d[k])) }
	theirName := strings.TrimSpace(str("givenName") + " " + str("familyName"))
	checks := []check{
		{Label: "Nombre y apellidos", Ours: p.FullName, Theirs: theirName, Match: fold(p.FullName) == fold(theirName)},
		{Label: "Nº de colegiado", Ours: p.CollegiateNumber, Theirs: e.CollegiateNumber, Match: p.CollegiateNumber == e.CollegiateNumber},
	}
	if pan := str("personal_administrative_number"); d["personal_administrative_number"] != nil {
		checks = append(checks, check{Label: "personal_administrative_number", Ours: p.AdministrativeNumber + " / " + p.CollegiateNumber,
			Theirs: pan, Match: pan == p.AdministrativeNumber || pan == p.CollegiateNumber})
	}
	if p.Specialty != "" {
		theirs := str("medical_speciality")
		checks = append(checks, check{Label: "Especialidad", Ours: p.Specialty, Theirs: theirs,
			Match: strings.Contains(fold(theirs), fold(p.Specialty))})
	}
	checks = append(checks, check{Label: "Habilitado para ejercer", Theirs: str("legally_entitled"), Info: true})
	return checks
}

func fold(s string) string {
	var b strings.Builder
	for _, r := range norm.NFD.String(strings.ToUpper(s)) {
		if unicode.Is(unicode.Mn, r) {
			continue
		}
		b.WriteRune(r)
	}
	return strings.Join(strings.Fields(b.String()), " ")
}
