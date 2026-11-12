// Command fakeadapter runs the in-memory stand-in of the enrolment API for
// local demos, with a small page (/_sim) to play the physician, the CGCOM
// registry and the clock: each button moves an enrolment and sends the
// signed webhook to the platform.
//
// Not the real system: it is written from the contract and exists so the
// platform can be exercised without the DEV environment.
package main

import (
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/fikua/fikua-vitalia/internal/adapter"
	"github.com/fikua/fikua-vitalia/internal/adapterstub"
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

	mux := http.NewServeMux()
	mux.Handle("/api/", stub.Handler())
	mux.HandleFunc("GET /_sim", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = simPage.Execute(w, map[string]any{"Rows": stub.Snapshot(), "Actions": adapterstub.Actions, "Msg": r.URL.Query().Get("msg")})
	})
	mux.HandleFunc("POST /_sim/{id}/{action}", func(w http.ResponseWriter, r *http.Request) {
		sent, err := stub.Act(r.Context(), r.PathValue("id"), r.PathValue("action"))
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
	})

	addr := env("FAKE_LISTEN_ADDR", ":8090")
	logger.Info("fake adapter listening", "addr", addr, "webhook_url", stub.WebhookURL, "token_required", stub.Token != "")
	srv := &http.Server{Addr: addr, Handler: http.NewCrossOriginProtection().Handler(mux), ReadHeaderTimeout: 10 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		logger.Error("fake adapter stopped", "err", err)
		os.Exit(1)
	}
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
code{font-size:12px}form{display:inline}button{margin:2px;padding:4px 8px;cursor:pointer}.msg{background:#eef;padding:8px;border-radius:6px}</style></head>
<body><h1>Simulador del sistema DoctorID (local)</h1>
<p>Hace de médico, registro colegial y reloj. Cada botón cambia la inscripción y envía el webhook firmado a la plataforma.</p>
{{with .Msg}}<p class="msg">{{.}}</p>{{end}}
<table><tr><th>Inscripción</th><th>Estado</th><th>Colegiado</th><th>Acciones</th></tr>
{{range $e := .Rows}}<tr><td><code>{{$e.ID}}</code></td><td>{{$e.State}}{{with $e.AuthSourcesCause}} ({{.}}){{end}}</td><td>{{$e.CollegiateNumber}}</td>
<td>{{range $a := $.Actions}}{{if canDo $e.State $a}}<form method="post" action="/_sim/{{$e.ID}}/{{$a}}"><button>{{$a}}</button></form>{{end}}{{end}}</td></tr>
{{else}}<tr><td colspan="4">Sin inscripciones. Da de alta un profesional en la plataforma.</td></tr>{{end}}
</table>
<p><small>Escenarios por nº de colegiado: acaba en 0 → ya tiene DoctorID; empieza por 999 → emisor caído (503).</small></p>
</body></html>`))
