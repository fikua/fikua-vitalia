package web_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/fikua/fikua-vitalia/internal/adapterstub"
	"github.com/fikua/fikua-vitalia/internal/cgcom"
	"github.com/fikua/fikua-vitalia/internal/doctorlogin"
	"github.com/fikua/fikua-vitalia/internal/enrollment"
	"github.com/fikua/fikua-vitalia/internal/idpstub"
	"github.com/fikua/fikua-vitalia/internal/store"
	"github.com/fikua/fikua-vitalia/internal/store/storetest"
	"github.com/fikua/fikua-vitalia/internal/web"
	"github.com/fikua/fikua-vitalia/internal/webhook"
)

// TestDoctorSignsInWithDoctorID drives the whole professional area through
// HTTP: the clinic, the simulated IdP and a browser with cookies.
func TestDoctorSignsInWithDoctorID(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st := storetest.Open(t)

	clinic := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(clinic.Close)
	idpSrv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(idpSrv.Close)
	idp := &idpstub.IdP{Issuer: idpSrv.URL, Holders: func() []idpstub.Holder {
		return []idpstub.Holder{{CollegiateNumber: "282810001", GivenName: "LAIA", FamilyName: "PUIG SOLER"}}
	}, Client: idpstub.Client{ID: "vitalia", RedirectURI: clinic.URL + "/profesional/callback", JWKSURL: clinic.URL + "/.well-known/jwks.json"}}
	idpSrv.Config.Handler = idp.Handler()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	login, err := doctorlogin.New(doctorlogin.Config{Issuer: idpSrv.URL, ClientID: "vitalia",
		RedirectURL: clinic.URL + "/profesional/callback", Scopes: []string{"openid", "doctorid"}, SigningKey: key})
	if err != nil {
		t.Fatal(err)
	}
	adapterSrv := httptest.NewServer((&adapterstub.Stub{}).Handler())
	t.Cleanup(adapterSrv.Close)
	u, _ := url.Parse(adapterSrv.URL)
	svc := enrollment.New(st, cgcom.NewClient(u, &http.Client{}, cgcom.StaticTokenSource("t"), st), logger, false)
	ui, err := web.New(web.Config{UIUser: "rrhh", UIPassword: "x"}, st, svc,
		&webhook.Receiver{Secret: secret, Tolerance: time.Minute, Sink: st, Logger: logger}, login, logger)
	if err != nil {
		t.Fatal(err)
	}
	clinic.Config.Handler = ui.Handler()

	// The physician's record, enrolment completed.
	p, _ := st.FindOrCreatePractitioner(ctx, store.Practitioner{FullName: "Laia Puig Soler", AdministrativeNumber: "11111111H", CollegiateNumber: "282810001"})
	now := time.Now()
	_, _ = st.UpsertEnrollment(ctx, p.ID, cgcom.Enrollment{ID: "6a0d7f3c-2b1e-4e8a-9c55-1f0b2d3e4a5b", State: cgcom.Completed,
		CollegiateNumber: "282810001", UpdatedAt: &now}, []byte(`{}`), true)

	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar}
	get := func(u string) (int, string) {
		resp, err := browser.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(b)
	}

	if code, body := get(clinic.URL + "/"); code != 200 || !strings.Contains(body, "Área profesional") {
		t.Fatalf("home: %d", code)
	}
	if code, body := get(clinic.URL + "/profesional"); code != 200 || !strings.Contains(body, "Acceder con DoctorID") {
		t.Fatalf("professional sign-in page: %d", code)
	}
	if code, body := get(clinic.URL + "/.well-known/jwks.json"); code != 200 || !strings.Contains(body, `"kty":"EC"`) {
		t.Fatalf("jwks: %d %s", code, body)
	}

	// Following redirects: clinic -> IdP login page.
	code, page := get(clinic.URL + "/profesional/entrar")
	m := regexp.MustCompile(`name="req" value="([^"]+)"`).FindStringSubmatch(page)
	if code != 200 || m == nil {
		t.Fatalf("IdP page: %d", code)
	}
	// Present the DoctorID: IdP -> clinic callback -> professional space.
	resp, err := browser.PostForm(idpSrv.URL+"/authorize", url.Values{"req": {m[1]}, "doctorid": {"282810001"}})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "Hola, Laia") || !strings.Contains(string(body), "Tu agenda de hoy") {
		t.Fatalf("professional space: %d %s", resp.StatusCode, body)
	}

	// The outsider is refused with a clear page.
	jar2, _ := cookiejar.New(nil)
	browser.Jar = jar2
	_, page = get(clinic.URL + "/profesional/entrar")
	m = regexp.MustCompile(`name="req" value="([^"]+)"`).FindStringSubmatch(page)
	resp, _ = browser.PostForm(idpSrv.URL+"/authorize", url.Values{"req": {m[1]}, "doctorid": {idpstub.Outsider.CollegiateNumber}})
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "no constas como profesional") {
		t.Fatalf("outsider: %d", resp.StatusCode)
	}

	logins, _ := st.RecentLogins(ctx, 10)
	if len(logins) != 2 || logins[0].Outcome != store.LoginDenied || logins[1].Outcome != store.LoginGranted {
		t.Fatalf("login log = %+v", logins)
	}
}
