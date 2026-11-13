package web_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fikua/fikua-vitalia/internal/adapter"
	"github.com/fikua/fikua-vitalia/internal/adapterstub"
	"github.com/fikua/fikua-vitalia/internal/enrollment"
	"github.com/fikua/fikua-vitalia/internal/store"
	"github.com/fikua/fikua-vitalia/internal/web"
	"github.com/fikua/fikua-vitalia/internal/webhook"
)

var secret = []byte("0123456789abcdef0123456789abcdef")

func newServer(t *testing.T) *httptest.Server {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	stub := &adapterstub.Stub{PortalURL: "https://portal.test/"}
	adapterSrv := httptest.NewServer(stub.Handler())
	t.Cleanup(adapterSrv.Close)
	u, _ := url.Parse(adapterSrv.URL)
	client := adapter.NewClient(u, &http.Client{Timeout: 5 * time.Second}, adapter.StaticTokenSource("tok"), st)
	svc := enrollment.New(st, client, logger, false)
	receiver := &webhook.Receiver{Secret: secret, Tolerance: 5 * time.Minute, Sink: st, Logger: logger}
	ui, err := web.New(web.Config{UIUser: "admision", UIPassword: "pass-de-pruebas"}, st, svc, receiver, nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(ui.Handler())
	t.Cleanup(srv.Close)
	return srv
}

func noRedirect() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func login(t *testing.T, srv *httptest.Server, password string) *http.Response {
	t.Helper()
	resp, err := noRedirect().PostForm(srv.URL+"/gestion/acceso", url.Values{"user": {"admision"}, "password": {password}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

func TestUIRequiresLogin(t *testing.T) {
	srv := newServer(t)
	for _, path := range []string{"/gestion/profesionales", "/gestion/registro", "/gestion/profesionales/nuevo"} {
		resp, err := noRedirect().Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/gestion/acceso" {
			t.Errorf("%s: %d %s, want redirect to /login", path, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
	if resp := login(t, srv, "wrong"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d", resp.StatusCode)
	}
}

func TestLoginEnrolAndCrossOriginPost(t *testing.T) {
	srv := newServer(t)
	resp := login(t, srv, "pass-de-pruebas")
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login: %d", resp.StatusCode)
	}
	cookie := resp.Cookies()[0]

	form := url.Values{"full_name": {"Laia Puig"}, "administrative_number": {"12345678Z"}, "collegiate_number": {"282812345"}}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/gestion/profesionales", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	resp, err := noRedirect().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/gestion/profesionales/") {
		t.Fatalf("enrol: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}

	// The same POST from another site is refused.
	req, _ = http.NewRequest(http.MethodPost, srv.URL+"/gestion/profesionales", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.AddCookie(cookie)
	resp, err = noRedirect().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site POST: %d, want 403", resp.StatusCode)
	}

	// The detail page renders.
	req, _ = http.NewRequest(http.MethodGet, srv.URL+"/gestion/profesionales/1", nil)
	req.AddCookie(cookie)
	resp, err = noRedirect().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "https://portal.test/") {
		t.Fatalf("detail: %d", resp.StatusCode)
	}
}

func TestWebhookAndHealthNeedNoSession(t *testing.T) {
	srv := newServer(t)
	body := []byte(`{"event_id":"11111111-1111-4111-8111-111111111111","event":"enrollment_state_changed","enrollment":{"id":"22222222-2222-4222-8222-222222222222","state":"EXPIRED","collegiate_number":"282812345"}}`)
	status, _, err := webhook.Send(context.Background(), &http.Client{}, srv.URL+web.WebhookPath, secret, body, time.Now())
	if err != nil || status != http.StatusOK {
		t.Fatalf("signed webhook: %d %v", status, err)
	}
	status, _, _ = webhook.Send(context.Background(), &http.Client{}, srv.URL+web.WebhookPath, []byte("wrong-secret-wrong-secret-wrong-s"), body, time.Now())
	if status != http.StatusUnauthorized {
		t.Fatalf("badly signed webhook: %d", status)
	}
	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz: %v %v", resp, err)
	}
	resp.Body.Close()
}

func TestStaticAssetsAreVersioned(t *testing.T) {
	srv := newServer(t)
	resp, err := http.Get(srv.URL + "/gestion/acceso")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), `href="/static/app.css?v=`) {
		t.Fatal("stylesheet link is not versioned")
	}
	resp, err = http.Get(srv.URL + "/static/app.css?v=x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "immutable") {
		t.Fatalf("versioned asset Cache-Control = %q", cc)
	}
	resp, _ = http.Get(srv.URL + "/static/app.css")
	resp.Body.Close()
	if cc := resp.Header.Get("Cache-Control"); cc != "no-cache" {
		t.Fatalf("unversioned asset Cache-Control = %q", cc)
	}
	if resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("only the fonts are shared with other origins")
	}
	// The clinic's Authentik pages load the font and the logo from here.
	for path, cors := range map[string]bool{"/static/fonts/figtree-latin.woff2": true, "/static/logo-vitalia.svg": false} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || (resp.Header.Get("Access-Control-Allow-Origin") == "*") != cors {
			t.Fatalf("%s: %d, CORS %q", path, resp.StatusCode, resp.Header.Get("Access-Control-Allow-Origin"))
		}
	}
}
