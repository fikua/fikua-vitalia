package web

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"slices"
	"sync"
	"time"
)

const (
	sessionCookie = "vitalia_session"
	sessionTTL    = 12 * time.Hour
)

// sessions is an in-memory session table: a restart logs everyone out,
// which is fine for a test platform with one operator account.
type sessions struct {
	mu   sync.Mutex
	byID map[string]time.Time
	data map[string]any
}

func (s *sessions) create() string { return s.createWith(nil) }

// get returns the data stored with a valid session.
func (s *sessions) get(id string) (any, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.byID[id]
	if !ok || time.Now().After(exp) {
		return nil, false
	}
	return s.data[id], true
}

func (s *sessions) createWith(v any) string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	id := base64.RawURLEncoding.EncodeToString(b[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byID == nil {
		s.byID, s.data = map[string]time.Time{}, map[string]any{}
	}
	now := time.Now()
	for k, exp := range s.byID { // drop expired ones
		if now.After(exp) {
			delete(s.byID, k)
			delete(s.data, k)
		}
	}
	s.byID[id] = now.Add(sessionTTL)
	s.data[id] = v
	return id
}

func (s *sessions) valid(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.byID[id]
	return ok && time.Now().Before(exp)
}

func (s *sessions) delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byID, id)
	delete(s.data, id)
}

// equalSecret compares in constant time regardless of length.
func equalSecret(a, b string) bool {
	ha, hb := sha256.Sum256([]byte(a)), sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}

func (s *Server) requireLogin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil || !s.sessions.valid(c.Value) {
			http.Redirect(w, r, "/gestion/acceso", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) loginForm(w http.ResponseWriter, r *http.Request) {
	s.renderLogin(w, r, "")
}

func (s *Server) renderLogin(w http.ResponseWriter, r *http.Request, errText string) {
	s.render(w, r, "admin_login.html", map[string]any{"Title": "Acceso a gestión", "Area": "admin-out", "Error": errText,
		"SSO": s.cfg.StaffLogin != nil, "Password": s.cfg.UIUser != "" && !(s.cfg.HidePasswordForm && s.cfg.StaffLogin != nil)})
}

func (s *Server) loginPost(w http.ResponseWriter, r *http.Request) {
	if s.cfg.UIUser == "" {
		http.NotFound(w, r)
		return
	}
	userOK := equalSecret(r.PostFormValue("user"), s.cfg.UIUser)
	passOK := equalSecret(r.PostFormValue("password"), s.cfg.UIPassword)
	if !userOK || !passOK {
		s.logger.Warn("failed login", "remote", r.RemoteAddr)
		w.WriteHeader(http.StatusUnauthorized)
		s.renderLogin(w, r, "Usuario o contraseña incorrectos.")
		return
	}
	s.startStaffSession(w, r)
}

func (s *Server) startStaffSession(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: s.sessions.create(), Path: "/", HttpOnly: true,
		Secure: s.cfg.CookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: int(sessionTTL.Seconds()),
	})
	http.Redirect(w, r, "/gestion/profesionales", http.StatusSeeOther)
}

const staffStateCookie = "vitalia_staff_state"

// staffStart sends the staff member to the clinic's identity provider.
func (s *Server) staffStart(w http.ResponseWriter, r *http.Request) {
	if s.cfg.StaffLogin == nil {
		http.Redirect(w, r, "/gestion/acceso", http.StatusSeeOther)
		return
	}
	authURL, state, err := s.cfg.StaffLogin.Start(r.Context())
	if err != nil {
		s.logger.Error("start staff login", "err", err)
		w.WriteHeader(http.StatusBadGateway)
		s.renderLogin(w, r, "El servicio de identidad de la clínica no responde. Inténtalo en unos minutos.")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: staffStateCookie, Value: state, Path: "/gestion", HttpOnly: true,
		Secure: s.cfg.CookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	http.Redirect(w, r, authURL, http.StatusFound)
}

// staffCallback finishes the staff login: the ID Token must list the
// staff group.
func (s *Server) staffCallback(w http.ResponseWriter, r *http.Request) {
	if s.cfg.StaffLogin == nil {
		http.NotFound(w, r)
		return
	}
	browserState := ""
	if c, err := r.Cookie(staffStateCookie); err == nil {
		browserState = c.Value
	}
	http.SetCookie(w, &http.Cookie{Name: staffStateCookie, Value: "", Path: "/gestion", MaxAge: -1, HttpOnly: true, Secure: s.cfg.CookieSecure})
	id, err := s.cfg.StaffLogin.Finish(r.Context(), r.URL.Query(), browserState)
	if err != nil {
		s.logger.Warn("staff login failed", "err", err)
		w.WriteHeader(http.StatusUnauthorized)
		s.renderLogin(w, r, "No se ha podido completar el inicio de sesión con la cuenta de la clínica.")
		return
	}
	if !slices.Contains(id.Groups, s.cfg.StaffGroup) {
		s.logger.Warn("staff login denied: not in the staff group", "subject", id.Subject, "group", s.cfg.StaffGroup)
		w.WriteHeader(http.StatusForbidden)
		s.renderLogin(w, r, "Tu cuenta de la clínica no tiene acceso a la gestión de profesionales.")
		return
	}
	s.logger.Info("staff login granted", "subject", id.Subject, "username", id.Username)
	s.startStaffSession(w, r)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.sessions.delete(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.cfg.CookieSecure})
	http.Redirect(w, r, "/gestion/acceso", http.StatusSeeOther)
}
