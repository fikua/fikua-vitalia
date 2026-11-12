// Command fakeadapter runs the stand-ins of the DoctorID systems for local
// demos and the phase 1 deployment:
//
//   - the enrolment API (internal listener, server to server);
//   - the identity provider the physicians sign in with (public listener);
//   - /_sim, a page to play the physician, the CGCOM registry and the clock:
//     each button moves an enrolment and sends the signed webhook.
//
// Not the real systems: written from the contracts so the clinic can be
// exercised without the DEV environment.
package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/fikua/fikua-vitalia/internal/adapter"
	"github.com/fikua/fikua-vitalia/internal/adapterstub"
	"github.com/fikua/fikua-vitalia/internal/idpstub"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secret := env("FAKE_WEBHOOK_SECRET", os.Getenv("VITALIA_WEBHOOK_SECRET"))
	if len(secret) < 32 {
		logger.Error("FAKE_WEBHOOK_SECRET (or VITALIA_WEBHOOK_SECRET) of at least 32 characters is required")
		os.Exit(2)
	}
	stub := &adapterstub.Stub{
		Token:         os.Getenv("FAKE_TOKEN"),
		PortalURL:     env("FAKE_PORTAL_URL", "https://issuance-portal.example.test/"),
		WebhookURL:    env("FAKE_WEBHOOK_URL", "http://localhost:8080/webhooks/enrollments"),
		WebhookSecret: []byte(secret),
		HTTP:          &http.Client{Timeout: 10 * time.Second},
	}
	simUser, simPass := os.Getenv("FAKE_SIM_USER"), os.Getenv("FAKE_SIM_PASSWORD")
	guard := func(h http.Handler) http.Handler { return basicAuth(simUser, simPass, h) }

	// Internal listener: the enrolment API only.
	api := http.NewServeMux()
	api.Handle("/api/", stub.Handler())

	// Public listener: identity provider and simulator page.
	public := http.NewServeMux()
	public.Handle("GET /_sim", guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = simPage.Execute(w, map[string]any{"Rows": stub.Snapshot(), "Actions": adapterstub.Actions, "Msg": r.URL.Query().Get("msg")})
	})))
	public.Handle("POST /_sim/{id}/{action}", guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent, err := stub.ActWith(r.Context(), r.PathValue("id"), r.PathValue("action"),
			adapterstub.ActOptions{GivenName: r.PostFormValue("given_name"), FamilyName: r.PostFormValue("family_name")})
		msg := ""
		switch {
		case err != nil:
			msg = err.Error()
		case sent.Err != nil:
			msg = "webhook not delivered: " + sent.Err.Error()
		default:
			msg = fmt.Sprintf("webhook delivered: HTTP %d %s", sent.Status, sent.Body)
		}
		logger.Info("sim action", "enrollment", r.PathValue("id"), "action", r.PathValue("action"), "result", msg)
		http.Redirect(w, r, "/_sim?msg="+template.URLQueryEscaper(msg), http.StatusSeeOther)
	})))

	if issuer := os.Getenv("FAKE_IDP_ISSUER"); issuer != "" {
		idp := &idpstub.IdP{
			Issuer: issuer,
			Client: idpstub.Client{
				ID:          env("FAKE_IDP_CLIENT_ID", "vitalia"),
				RedirectURI: env("FAKE_IDP_REDIRECT_URI", "http://localhost:8080/profesional/callback"),
				JWKSURL:     env("FAKE_IDP_CLIENT_JWKS_URL", "http://localhost:8080/.well-known/jwks.json"),
			},
			Holders: stub.Holders,
			HTTP:    &http.Client{Timeout: 10 * time.Second},
		}
		h := idp.Handler()
		public.Handle("GET /.well-known/openid-configuration", h)
		public.Handle("GET /jwks", h)
		public.Handle("POST /token", h)       // server to server, client authenticated by its assertion
		public.Handle("/authorize", guard(h)) // the "wallet": only for people with the simulator password
		logger.Info("identity provider enabled", "issuer", issuer, "client_id", idp.Client.ID)
	}

	apiAddr, publicAddr := env("FAKE_LISTEN_ADDR", ":8090"), env("FAKE_PUBLIC_ADDR", ":8091")
	go func() {
		logger.Info("simulator public listener", "addr", publicAddr, "sim_password", simPass != "")
		srv := &http.Server{Addr: publicAddr, Handler: http.NewCrossOriginProtection().Handler(public), ReadHeaderTimeout: 10 * time.Second}
		if err := srv.ListenAndServe(); err != nil {
			logger.Error("public listener stopped", "err", err)
			os.Exit(1)
		}
	}()
	logger.Info("fake enrolment API listening", "addr", apiAddr, "webhook_url", stub.WebhookURL, "token_required", stub.Token != "")
	srv := &http.Server{Addr: apiAddr, Handler: api, ReadHeaderTimeout: 10 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		logger.Error("fake adapter stopped", "err", err)
		os.Exit(1)
	}
}

// basicAuth protects h when a user is configured.
func basicAuth(user, pass string, h http.Handler) http.Handler {
	if user == "" {
		return h
	}
	eq := func(a, b string) bool {
		x, y := sha256.Sum256([]byte(a)), sha256.Sum256([]byte(b))
		return subtle.ConstantTimeCompare(x[:], y[:]) == 1
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || !eq(u, user) || !eq(p, pass) {
			w.Header().Set("WWW-Authenticate", `Basic realm="Simulador DoctorID"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

var simPage = template.Must(template.New("sim").Funcs(template.FuncMap{
	"canDo": func(s adapter.State, a string) bool {
		switch a {
		case "obtain":
			return s == adapter.Initiated || s == adapter.PendingAuthSources || s == adapter.Completed
		case "mismatch", "dispute", "reject-registry":
			return s == adapter.Initiated || s == adapter.PendingAuthSources
		case "expire":
			return !s.Final() && s != adapter.Completed
		case "revoke", "renew":
			return s == adapter.PendingConfirmation || s == adapter.Completed
		}
		return false
	},
}).Parse(`<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Simulador DoctorID</title>
<style>body{font:14px system-ui,sans-serif;margin:0 auto;max-width:1100px;padding:16px;background:#fafafa;color:#222}
table{border-collapse:collapse;width:100%;background:#fff}td,th{border-bottom:1px solid #ddd;padding:8px;text-align:left;vertical-align:top}
code{font-size:12px}form{display:inline}button{margin:2px;padding:4px 8px;cursor:pointer}.msg{background:#eef;padding:8px;border-radius:6px}.obtain{display:block;margin:2px 0}input{padding:3px 5px;margin-right:4px}</style></head>
<body><h1>Simulador del sistema DoctorID</h1>
<p>Hace de médico, de registro colegial y de reloj. Cada botón cambia la inscripción y envía el webhook firmado a la clínica.
«obtain» emite el DoctorID con el nombre y apellidos que indiques (los del registro colegial; vacío = inventados). A partir de ahí el médico puede presentarlo en el inicio de sesión.</p>
{{with .Msg}}<p class="msg">{{.}}</p>{{end}}
<table><tr><th>Inscripción</th><th>Estado</th><th>Colegiado</th><th>Acciones</th></tr>
{{range $e := .Rows}}<tr><td><code>{{$e.ID}}</code></td><td>{{$e.State}}{{with $e.AuthSourcesCause}} ({{.}}){{end}}</td><td>{{$e.CollegiateNumber}}</td>
<td>{{range $a := $.Actions}}{{if canDo $e.State $a}}{{if eq $a "obtain"}}<form class="obtain" method="post" action="/_sim/{{$e.ID}}/obtain"><input name="given_name" placeholder="Nombre (colegio)" size="12"><input name="family_name" placeholder="Apellidos" size="16"><button>obtain</button></form>{{else}}<form method="post" action="/_sim/{{$e.ID}}/{{$a}}"><button>{{$a}}</button></form>{{end}}{{end}}{{end}}</td></tr>
{{else}}<tr><td colspan="4">Sin inscripciones. Da de alta un profesional en la clínica.</td></tr>{{end}}
</table>
<p><small>Escenarios por nº de colegiado: acaba en 0 → ya tiene DoctorID; empieza por 999 → emisor caído (503).</small></p>
</body></html>`))
