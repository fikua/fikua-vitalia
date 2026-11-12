package web

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
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
}

func (s *sessions) create() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	id := base64.RawURLEncoding.EncodeToString(b[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byID == nil {
		s.byID = map[string]time.Time{}
	}
	now := time.Now()
	for k, exp := range s.byID { // drop expired ones
		if now.After(exp) {
			delete(s.byID, k)
		}
	}
	s.byID[id] = now.Add(sessionTTL)
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
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) loginForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "login.html", map[string]any{"Title": "Acceso"})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	userOK := equalSecret(r.PostFormValue("user"), s.cfg.UIUser)
	passOK := equalSecret(r.PostFormValue("password"), s.cfg.UIPassword)
	if !userOK || !passOK {
		s.logger.Warn("failed login", "remote", r.RemoteAddr)
		w.WriteHeader(http.StatusUnauthorized)
		s.render(w, r, "login.html", map[string]any{"Title": "Acceso", "Error": "Usuario o contraseña incorrectos."})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: s.sessions.create(), Path: "/", HttpOnly: true,
		Secure: s.cfg.CookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: int(sessionTTL.Seconds()),
	})
	http.Redirect(w, r, "/profesionales", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.sessions.delete(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.cfg.CookieSecure})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
