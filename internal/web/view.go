package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
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
		checks = append(checks, check{Label: "Nº administrativo en el DoctorID", Ours: p.AdministrativeNumber + " / " + p.CollegiateNumber,
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

// ------------------------------------------------------------ list grouping

// Groups the operator filters the list by.
const (
	groupReview   = "revision"
	groupWaiting  = "espera"
	groupIssues   = "incidencias"
	groupVerified = "verificados"
	groupClosed   = "cerrados"
)

var filterOrder = []string{"", groupReview, groupWaiting, groupIssues, groupVerified, groupClosed}

var filterLabels = map[string]string{
	"":            "Todos",
	groupReview:   "Por revisar",
	groupWaiting:  "Esperando al médico",
	groupIssues:   "Incidencias",
	groupVerified: "Verificados",
	groupClosed:   "Cerrados",
}

func groupOf(e *store.Enrollment) string {
	if e == nil {
		return groupIssues
	}
	if e.InvalidatedReason != "" {
		return groupIssues
	}
	switch e.State {
	case adapter.PendingConfirmation:
		return groupReview
	case adapter.Initiated:
		return groupWaiting
	case adapter.PendingAuthSources:
		return groupIssues
	case adapter.Completed:
		return groupVerified
	}
	return groupClosed
}

// initials of a full name, for the avatar.
func initials(name string) string {
	var out []rune
	for _, w := range strings.Fields(name) {
		r := []rune(w)
		if len(r) > 0 && unicode.IsLetter(r[0]) {
			out = append(out, unicode.ToUpper(r[0]))
		}
		if len(out) == 2 {
			break
		}
	}
	return string(out)
}

// --------------------------------------------------------------- progress

type step struct {
	Label, Hint string
	Status      string // done | current | failed | todo
}

// steps maps the enrolment state onto the clinic's four-step journey.
func steps(s adapter.State) []step {
	st := []step{
		{Label: "Alta en Vitalia", Hint: "Ficha e inscripción enviadas", Status: "done"},
		{Label: "DoctorID del médico", Hint: "Lo obtiene en el Portal de Emisión", Status: "todo"},
		{Label: "Revisión de datos", Hint: "Admisión compara y confirma", Status: "todo"},
		{Label: "Verificado", Hint: "Puede identificarse con DoctorID", Status: "todo"},
	}
	switch s {
	case adapter.Initiated:
		st[1].Status = "current"
	case adapter.PendingAuthSources:
		st[1].Status, st[1].Hint = "blocked", "Su colegio debe corregir sus datos"
	case adapter.RejectedByRegistry:
		st[1].Status = "failed"
	case adapter.PendingConfirmation:
		st[1].Status, st[2].Status = "done", "current"
	case adapter.Completed:
		st[1].Status, st[2].Status, st[3].Status = "done", "done", "done"
	case adapter.Expired, adapter.Cancelled:
		st[1].Status = "failed"
	}
	return st
}

// --------------------------------------------------------------- activity

type activityItem struct {
	At     time.Time
	Kind   string // in | out
	Title  string
	Meta   string
	Tone   string
	Note   string
	Bodies []labelled
}

type labelled struct{ Label, Body string }

// activity merges received webhooks and outgoing calls into one timeline,
// newest first.
func activity(hooks []store.WebhookEvent, calls []adapter.Call) []activityItem {
	var out []activityItem
	for _, h := range hooks {
		sig := "firma válida"
		if !h.SignatureValid {
			sig = "firma no válida: " + h.SignatureError
		}
		note := h.StatusDetail
		out = append(out, activityItem{At: h.ReceivedAt, Kind: "in", Title: "Aviso recibido · " + eventLabel(h.Event),
			Meta: h.Status + " · " + sig, Tone: webhookTone(h.Status), Note: note,
			Bodies: []labelled{{"Cuerpo del aviso", h.RawBody}}})
	}
	for _, c := range calls {
		tone := "bad"
		if c.Status >= 200 && c.Status < 300 {
			tone = "ok"
		}
		status := "sin respuesta"
		if c.Status != 0 {
			status = fmt.Sprintf("HTTP %d", c.Status)
		}
		if c.ProblemType != "" {
			status += " · " + c.ProblemType
		}
		if c.RetryAfter != "" {
			status += " · Retry-After " + c.RetryAfter
		}
		it := activityItem{At: c.At, Kind: "out", Title: "Llamada · " + operationLabel(c.Operation),
			Meta: c.Method + " " + c.Path + " · " + status, Tone: tone, Note: c.Error}
		if c.RequestBody != "" {
			it.Bodies = append(it.Bodies, labelled{"Petición", c.RequestBody})
		}
		if c.ResponseBody != "" {
			it.Bodies = append(it.Bodies, labelled{"Respuesta", c.ResponseBody})
		}
		out = append(out, it)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.After(out[j].At) })
	return out
}

func operationLabel(op string) string {
	switch op {
	case "createEnrollment":
		return "inscribir"
	case "getEnrollment":
		return "consultar estado"
	case "confirmEnrollment":
		return "confirmar o rechazar"
	case "cancelEnrollment":
		return "cancelar"
	}
	return op
}

func filterHref(f string) string {
	if f == "" {
		return "/profesionales"
	}
	return "/profesionales?estado=" + f
}
