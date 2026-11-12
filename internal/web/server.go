// Package web is the clinic's operator UI and the HTTP entry point that
// also mounts the webhook receiver.
package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/fikua/fikua-vitalia/internal/adapter"
	"github.com/fikua/fikua-vitalia/internal/enrollment"
	"github.com/fikua/fikua-vitalia/internal/store"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// Config is the part of the configuration the UI needs.
type Config struct {
	UIUser       string
	UIPassword   string
	CookieSecure bool
	AdapterHost  string // shown in the technical log, never the token
}

// Server serves the UI.
type Server struct {
	cfg      Config
	store    *store.Store
	service  *enrollment.Service
	webhook  http.Handler
	logger   *slog.Logger
	pages    map[string]*template.Template
	sessions sessions
	loc      *time.Location
}

// WebhookPath is where the adapter posts notifications.
const WebhookPath = "/webhooks/enrollments"

// New builds the server.
func New(cfg Config, st *store.Store, svc *enrollment.Service, webhook http.Handler, logger *slog.Logger) (*Server, error) {
	loc, err := time.LoadLocation("Europe/Madrid")
	if err != nil {
		loc = time.UTC
	}
	s := &Server{cfg: cfg, store: st, service: svc, webhook: webhook, logger: logger, pages: map[string]*template.Template{}, loc: loc}
	funcs := template.FuncMap{
		"stateLabel": stateLabel, "stateTone": stateTone, "causeLabel": causeLabel,
		"time": s.fmtTime, "timep": s.fmtTimePtr, "pretty": prettyJSON, "deref": deref,
		"dataValue": dataValue, "eventLabel": eventLabel, "webhookTone": webhookTone,
		"initials": initials, "filterHref": filterHref, "operationLabel": operationLabel,
	}
	assets, err := assetVersions()
	if err != nil {
		return nil, err
	}
	funcs["asset"] = func(name string) string { return "/static/" + name + "?v=" + assets[name] }
	pages, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	for _, p := range pages {
		name := strings.TrimPrefix(p, "templates/")
		if name == "layout.html" {
			continue
		}
		t, err := template.New("layout.html").Funcs(funcs).ParseFS(templateFS, "templates/layout.html", p)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", name, err)
		}
		s.pages[name] = t
	}
	return s, nil
}

// Handler returns the full HTTP handler.
func (s *Server) Handler() http.Handler {
	ui := http.NewServeMux()
	ui.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/profesionales", http.StatusSeeOther)
	})
	ui.HandleFunc("GET /profesionales", s.list)
	ui.HandleFunc("GET /profesionales/nuevo", s.newForm)
	ui.HandleFunc("POST /profesionales", s.create)
	ui.HandleFunc("GET /profesionales/{id}", s.detail)
	ui.HandleFunc("POST /profesionales/{id}/inscribir", s.enrolAgain)
	ui.HandleFunc("POST /inscripciones/{id}/{action}", s.act)
	ui.HandleFunc("GET /registro", s.techLog)
	ui.HandleFunc("POST /logout", s.logout)

	root := http.NewServeMux()
	root.Handle("POST "+WebhookPath, s.webhook) // server-to-server: no session, no CSRF check
	root.HandleFunc("GET /healthz", s.health)
	static, _ := fs.Sub(staticFS, "static")
	root.Handle("GET /static/", staticCache(http.StripPrefix("/static/", http.FileServerFS(static))))
	root.HandleFunc("GET /login", s.loginForm)
	root.Handle("POST /login", http.NewCrossOriginProtection().Handler(http.HandlerFunc(s.login)))
	root.Handle("/", s.requireLogin(http.NewCrossOriginProtection().Handler(ui)))
	return securityHeaders(root)
}

// assetVersions hashes every static file, so templates can link
// /static/x?v=<hash>: a new deploy changes the URL and no cache (browser or
// Cloudflare) serves a stale stylesheet against new HTML.
func assetVersions() (map[string]string, error) {
	out := map[string]string{}
	err := fs.WalkDir(staticFS, "static", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := staticFS.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		out[strings.TrimPrefix(path, "static/")] = hex.EncodeToString(sum[:])[:12]
		return nil
	})
	return out, err
}

// staticCache lets versioned URLs be cached forever and makes unversioned
// ones revalidate.
func staticCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("v") != "" {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		next.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		http.Error(w, "database unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}

// ------------------------------------------------------------------- pages

func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.ListPractitioners(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	filter := r.URL.Query().Get("estado")
	if _, ok := filterLabels[filter]; !ok {
		filter = ""
	}
	counts := map[string]int{"": len(rows)}
	var shown []store.PractitionerRow
	for _, row := range rows {
		g := groupOf(row.Latest)
		counts[g]++
		if filter == "" || filter == g {
			shown = append(shown, row)
		}
	}
	s.render(w, r, "list.html", map[string]any{"Title": "Profesionales", "Rows": shown, "Total": len(rows),
		"Counts": counts, "Filter": filter, "Filters": filterOrder, "FilterLabels": filterLabels, "Nav": "list"})
}

func (s *Server) newForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "new.html", map[string]any{"Title": "Alta de profesional", "Nav": "new", "Form": map[string]string{}})
}

func (s *Server) create(w http.ResponseWriter, r *http.Request) {
	in := enrollment.NewPractitioner{
		FullName:             r.PostFormValue("full_name"),
		AdministrativeNumber: r.PostFormValue("administrative_number"),
		CollegiateNumber:     r.PostFormValue("collegiate_number"),
		Specialty:            r.PostFormValue("specialty"),
		Email:                r.PostFormValue("email"),
	}
	p, err := s.service.Enrol(r.Context(), in)
	var verr *enrollment.ValidationError
	if errors.As(err, &verr) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.render(w, r, "new.html", map[string]any{"Title": "Alta de profesional", "Nav": "new", "Errors": verr.Fields,
			"Form": map[string]string{"full_name": in.FullName, "administrative_number": in.AdministrativeNumber,
				"collegiate_number": in.CollegiateNumber, "specialty": in.Specialty, "email": in.Email}})
		return
	}
	if p.ID == 0 {
		s.fail(w, r, err)
		return
	}
	if err != nil {
		s.flashError(w, "El profesional se ha guardado, pero la inscripción no se ha podido enviar.", err)
	} else {
		setFlash(w, flash{Kind: "ok", Text: "Profesional dado de alta e inscripción enviada."})
	}
	http.Redirect(w, r, fmt.Sprintf("/profesionales/%d", p.ID), http.StatusSeeOther)
}

type enrollView struct {
	store.Enrollment
	E      adapter.Enrollment
	Checks []check
}

type check struct {
	Label, Ours, Theirs string
	Match               bool
	Info                bool // no comparison possible
}

func (s *Server) detail(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	p, err := s.store.Practitioner(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	list, err := s.store.EnrollmentsOf(ctx, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	data := map[string]any{"Title": p.FullName, "P": p, "Nav": "list"}
	if len(list) > 0 {
		cur := enrollView{Enrollment: list[0], E: list[0].Decoded()}
		cur.Checks = compare(p, cur.E)
		data["Current"] = cur
		data["Steps"] = steps(cur.State)
		data["History"] = list[1:]
		hooks, err := s.store.WebhooksOf(ctx, cur.ID)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		calls, err := s.store.CallsOf(ctx, cur.ID)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		data["Activity"] = activity(hooks, calls)
	}
	s.render(w, r, "detail.html", data)
}

func (s *Server) enrolAgain(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	p, err := s.store.Practitioner(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := s.service.EnrolAgain(r.Context(), p); err != nil {
		s.flashError(w, "No se ha podido enviar la inscripción.", err)
	} else {
		setFlash(w, flash{Kind: "ok", Text: "Inscripción enviada."})
	}
	http.Redirect(w, r, fmt.Sprintf("/profesionales/%d", p.ID), http.StatusSeeOther)
}

func (s *Server) act(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	e, err := s.store.Enrollment(ctx, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	var ok string
	switch r.PathValue("action") {
	case "refrescar":
		err, ok = s.service.Refresh(ctx, id), "Estado actualizado desde el sistema DoctorID."
	case "confirmar":
		err, ok = s.service.Decide(ctx, id, adapter.Confirm), "Datos confirmados. El profesional queda verificado."
	case "rechazar":
		err, ok = s.service.Decide(ctx, id, adapter.Reject), "Datos rechazados. La inscripción queda cancelada."
	case "cancelar":
		err, ok = s.service.Cancel(ctx, id), "Inscripción cancelada."
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.flashError(w, "La operación no se ha completado.", err)
	} else {
		setFlash(w, flash{Kind: "ok", Text: ok})
	}
	http.Redirect(w, r, fmt.Sprintf("/profesionales/%d", e.PractitionerID), http.StatusSeeOther)
}

func (s *Server) techLog(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hooks, err := s.store.RecentWebhooks(ctx, 100)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	calls, err := s.store.RecentCalls(ctx, 100)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, "log.html", map[string]any{"Title": "Registro técnico", "Nav": "log", "Webhooks": hooks,
		"Calls": calls, "AdapterHost": s.cfg.AdapterHost, "WebhookPath": WebhookPath})
}

// ----------------------------------------------------------------- helpers

func (s *Server) render(w http.ResponseWriter, r *http.Request, page string, data map[string]any) {
	t, ok := s.pages[page]
	if !ok {
		http.Error(w, "page not found", http.StatusInternalServerError)
		return
	}
	if f, ok := takeFlash(w, r); ok {
		data["Flash"] = f
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout.html", data); err != nil {
		s.logger.Error("render", "page", page, "err", err)
		http.Error(w, "render error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	s.logger.Error("request failed", "path", r.URL.Path, "err", err)
	http.Error(w, "Error interno. Consulta los logs.", http.StatusInternalServerError)
}

type flash struct {
	Kind       string   `json:"k"`
	Text       string   `json:"t"`
	Detail     string   `json:"d,omitempty"`
	Violations []string `json:"v,omitempty"`
}

const flashCookie = "vitalia_flash"

func setFlash(w http.ResponseWriter, f flash) {
	if len(f.Detail) > 600 { // keep the cookie well under the 4 KB limit
		f.Detail = f.Detail[:600] + "…"
	}
	if len(f.Violations) > 10 {
		f.Violations = f.Violations[:10]
	}
	b, _ := json.Marshal(f)
	http.SetCookie(w, &http.Cookie{Name: flashCookie, Value: base64.RawURLEncoding.EncodeToString(b), Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 60})
}

func takeFlash(w http.ResponseWriter, r *http.Request) (flash, bool) {
	c, err := r.Cookie(flashCookie)
	if err != nil {
		return flash{}, false
	}
	http.SetCookie(w, &http.Cookie{Name: flashCookie, Value: "", Path: "/", MaxAge: -1})
	b, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return flash{}, false
	}
	var f flash
	if json.Unmarshal(b, &f) != nil {
		return flash{}, false
	}
	return f, true
}

// flashError turns an adapter error into what the operator needs: the
// problem type and detail, and when to retry.
func (s *Server) flashError(w http.ResponseWriter, text string, err error) {
	f := flash{Kind: "error", Text: text}
	var pe *adapter.ProblemError
	if errors.As(err, &pe) {
		f.Detail = fmt.Sprintf("HTTP %d", pe.Status)
		if pe.Problem.Type != "" {
			f.Detail += " · " + pe.Problem.Type
		}
		if pe.Problem.Detail != "" {
			f.Detail += " · " + pe.Problem.Detail
		}
		if pe.HasRetry {
			f.Detail += fmt.Sprintf(" · Vuelve a intentarlo dentro de %s (a partir de las %s).",
				pe.RetryAfter.Round(time.Second), time.Now().Add(pe.RetryAfter).In(s.loc).Format("15:04:05"))
		}
		for _, v := range pe.Problem.Violations {
			f.Violations = append(f.Violations, v.Field+": "+v.Message)
		}
	} else {
		s.logger.Warn("adapter call failed", "err", err)
		f.Detail = err.Error()
	}
	setFlash(w, f)
}
