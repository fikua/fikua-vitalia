package web

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/fikua/fikua-vitalia/internal/adapter"
	"github.com/fikua/fikua-vitalia/internal/doctorlogin"
	"github.com/fikua/fikua-vitalia/internal/store"
)

const (
	doctorCookie = "vitalia_dr"
	stateCookie  = "vitalia_oidc_state"
)

// doctorSession is what the clinic keeps about a signed-in physician.
type doctorSession struct {
	PractitionerID int64
	Identity       doctorlogin.Identity
	LoginAt        time.Time
}

// home is the clinic's public website.
func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "home.html", map[string]any{"Title": "Inicio", "Area": "public"})
}

func (s *Server) currentDoctor(r *http.Request) (*doctorSession, bool) {
	c, err := r.Cookie(doctorCookie)
	if err != nil {
		return nil, false
	}
	v, ok := s.doctors.get(c.Value)
	if !ok {
		return nil, false
	}
	d, ok := v.(*doctorSession)
	return d, ok
}

// proHome is the professional area: the sign-in page, or the physician's
// space when signed in.
func (s *Server) proHome(w http.ResponseWriter, r *http.Request) {
	d, ok := s.currentDoctor(r)
	if !ok {
		s.render(w, r, "pro_login.html", map[string]any{"Title": "Área profesional", "Area": "pro", "LoginEnabled": s.login != nil})
		return
	}
	p, err := s.store.Practitioner(r.Context(), d.PractitionerID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, "pro_home.html", map[string]any{"Title": "Mi espacio", "Area": "pro", "Doctor": d, "P": p,
		"Agenda": agendaFor(p.ID, time.Now().In(s.loc))})
}

// proStart redirects the physician to the identity provider.
func (s *Server) proStart(w http.ResponseWriter, r *http.Request) {
	if s.login == nil {
		http.Redirect(w, r, "/profesional", http.StatusSeeOther)
		return
	}
	authURL, state, err := s.login.Start(r.Context())
	if err != nil {
		s.logger.Error("start DoctorID login", "err", err)
		s.render(w, r, "pro_denied.html", map[string]any{"Title": "No se ha podido iniciar sesión", "Area": "pro",
			"Reason": doctorlogin.ReasonIdPError, "Detail": "El servicio de identificación DoctorID no responde. Inténtalo en unos minutos."})
		return
	}
	// The state is bound to this browser: a callback started elsewhere fails.
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Value: state, Path: "/profesional", HttpOnly: true,
		Secure: s.cfg.CookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	http.Redirect(w, r, authURL, http.StatusFound)
}

// proCallback finishes the login and applies the clinic's access rule.
func (s *Server) proCallback(w http.ResponseWriter, r *http.Request) {
	if s.login == nil {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	browserState := ""
	if c, err := r.Cookie(stateCookie); err == nil {
		browserState = c.Value
	}
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Value: "", Path: "/profesional", MaxAge: -1, HttpOnly: true, Secure: s.cfg.CookieSecure})

	id, err := s.login.Finish(ctx, r.URL.Query(), browserState)
	if err != nil {
		detail := "No se ha podido completar el inicio de sesión."
		var idpErr *doctorlogin.IdPError
		if errors.As(err, &idpErr) && idpErr.Code == "access_denied" {
			detail = "Has cancelado el inicio de sesión o no se ha podido verificar tu DoctorID."
		}
		s.logger.Warn("DoctorID login failed", "err", err)
		s.recordLogin(r, store.LoginEvent{Outcome: store.LoginDenied, Reason: doctorlogin.ReasonIdPError, Detail: err.Error()})
		w.WriteHeader(http.StatusUnauthorized)
		s.render(w, r, "pro_denied.html", map[string]any{"Title": "No se ha podido iniciar sesión", "Area": "pro",
			"Reason": doctorlogin.ReasonIdPError, "Detail": detail})
		return
	}

	decision, err := doctorlogin.Decide(ctx, s.store, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ev := store.LoginEvent{PractitionerID: decision.Practitioner.ID, CollegiateNumber: id.CollegiateNumber,
		Subject: id.Subject, ACR: id.ACR, AMR: strings.Join(id.AMR, " "), Claims: id.RawClaims}
	if !decision.Granted {
		ev.Outcome, ev.Reason = store.LoginDenied, decision.Reason
		if decision.State != "" {
			ev.Detail = "estado " + string(decision.State)
		}
		s.recordLogin(r, ev)
		s.logger.Info("DoctorID login denied", "reason", decision.Reason)
		w.WriteHeader(http.StatusForbidden)
		s.render(w, r, "pro_denied.html", map[string]any{"Title": "Acceso no permitido", "Area": "pro",
			"Reason": decision.Reason, "State": decision.State, "Identity": id})
		return
	}
	ev.Outcome = store.LoginGranted
	s.recordLogin(r, ev)
	s.logger.Info("DoctorID login granted", "practitioner_id", decision.Practitioner.ID)
	http.SetCookie(w, &http.Cookie{Name: doctorCookie, Path: "/", HttpOnly: true, Secure: s.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode, MaxAge: int(sessionTTL.Seconds()),
		Value: s.doctors.createWith(&doctorSession{PractitionerID: decision.Practitioner.ID, Identity: id, LoginAt: time.Now()})})
	http.Redirect(w, r, "/profesional", http.StatusSeeOther)
}

func (s *Server) recordLogin(r *http.Request, ev store.LoginEvent) {
	ev.At = time.Now()
	if err := s.store.RecordLogin(r.Context(), ev); err != nil {
		s.logger.Error("record login", "err", err)
	}
}

func (s *Server) proLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(doctorCookie); err == nil {
		s.doctors.delete(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: doctorCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.cfg.CookieSecure})
	setFlash(w, flash{Kind: "ok", Text: "Has cerrado la sesión en Clínica Vitalia."})
	http.Redirect(w, r, "/profesional", http.StatusSeeOther)
}

// unbind forgets the DoctorID identity bound to a practitioner.
func (s *Server) unbind(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := s.store.ResetDoctorIDBinding(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	setFlash(w, flash{Kind: "ok", Text: "DoctorID desvinculado. El próximo acceso con DoctorID volverá a vincularse."})
	http.Redirect(w, r, fmt.Sprintf("/gestion/profesionales/%d", id), http.StatusSeeOther)
}

// ----------------------------------------------------------------- helpers

type appointment struct {
	Time, Patient, Reason, Room string
}

// agendaFor builds a fictitious, stable agenda for the day.
func agendaFor(seed int64, day time.Time) []appointment {
	patients := []string{"A. M. R.", "J. P. S.", "L. G. T.", "C. V. N.", "M. R. B.", "S. L. F.", "P. C. A.", "E. D. M."}
	reasons := []string{"Primera visita", "Revisión", "Resultados de analítica", "Control de tratamiento", "Seguimiento", "Consulta preoperatoria"}
	n := int(seed) + day.YearDay()
	out := make([]appointment, 0, 6)
	for i := range 6 {
		h := 9 + i
		if i >= 3 {
			h++ // break at 12:00
		}
		out = append(out, appointment{
			Time: fmt.Sprintf("%02d:%02d", h, []int{0, 30}[(n+i)%2]), Patient: "Paciente " + patients[(n+i*3)%len(patients)],
			Reason: reasons[(n+i)%len(reasons)], Room: fmt.Sprintf("Consulta %d", 1+(n%4)),
		})
	}
	return out
}

func titleCase(s string) string {
	words := strings.Fields(strings.ToLower(s))
	for i, w := range words {
		r := []rune(w)
		r[0] = unicode.ToUpper(r[0])
		words[i] = string(r)
	}
	return strings.Join(words, " ")
}

func acrLabel(acr string) string {
	switch acr {
	case "http://eidas.europa.eu/LoA/high":
		return "Alto (eIDAS)"
	case "http://eidas.europa.eu/LoA/substantial":
		return "Sustancial (eIDAS)"
	case "http://eidas.europa.eu/LoA/low":
		return "Bajo (eIDAS)"
	case "":
		return "—"
	}
	return acr
}

func reasonLabel(reason string, state adapter.State) string {
	switch reason {
	case doctorlogin.ReasonNotRegistered:
		return "Tu DoctorID es válido, pero no constas como profesional de Clínica Vitalia. Si trabajas con nosotros, pide a Recursos Humanos que te den de alta."
	case doctorlogin.ReasonNotVerified:
		return fmt.Sprintf("Constas como profesional de la clínica, pero tu acceso con DoctorID aún no está habilitado (%s). Recursos Humanos debe completar tu alta.", strings.ToLower(stateLabel(state)))
	case doctorlogin.ReasonInvalidated:
		return "Tu DoctorID ha sido revocado o se está renovando. Cuando tengas el nuevo y Recursos Humanos lo confirme, podrás volver a entrar."
	case doctorlogin.ReasonIdentityMismatch:
		return "Este DoctorID no es el que está vinculado a tu ficha en la clínica. Contacta con Recursos Humanos."
	case doctorlogin.ReasonAmbiguous:
		return "Hay más de una ficha con tu número de colegiado. Contacta con Recursos Humanos para que lo revisen."
	case doctorlogin.ReasonMissingClaim:
		return "El servicio de identificación no ha enviado tu número de colegiado, así que no podemos saber quién eres."
	}
	return "No se ha podido completar el inicio de sesión."
}
