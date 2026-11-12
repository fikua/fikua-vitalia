package doctorlogin_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/fikua/fikua-vitalia/internal/adapter"
	"github.com/fikua/fikua-vitalia/internal/doctorlogin"
	"github.com/fikua/fikua-vitalia/internal/idpstub"
	"github.com/fikua/fikua-vitalia/internal/store"
)

type env struct {
	idp    *httptest.Server
	client *doctorlogin.Client
	st     *store.Store
}

var noFollow = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

// newEnv wires the clinic's relying party to the simulated IdP. The IdP
// fetches the clinic's JWKS to check its private_key_jwt assertions.
func newEnv(t *testing.T) *env {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	var client *doctorlogin.Client
	clinic := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(client.JWKS()) }))
	t.Cleanup(clinic.Close)

	idp := &idpstub.IdP{Holders: func() []idpstub.Holder {
		return []idpstub.Holder{{CollegiateNumber: "282810001", GivenName: "LAIA", FamilyName: "PUIG SOLER",
			Data: map[string]any{"medical_speciality": []string{"Pediatría"}}}}
	}}
	idpSrv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(idpSrv.Close)
	idp.Issuer = idpSrv.URL
	idp.Client = idpstub.Client{ID: "vitalia", RedirectURI: clinic.URL + "/profesional/callback", JWKSURL: clinic.URL + "/jwks"}
	idpSrv.Config.Handler = idp.Handler()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client, err = doctorlogin.New(doctorlogin.Config{Issuer: idpSrv.URL, ClientID: "vitalia",
		RedirectURL: clinic.URL + "/profesional/callback", Scopes: []string{"openid", "profile", "doctorid"}, SigningKey: key})
	if err != nil {
		t.Fatal(err)
	}
	return &env{idp: idpSrv, client: client, st: st}
}

var reqRE = regexp.MustCompile(`name="req" value="([^"]+)"`)

// login runs the browser part: start, the IdP page, the choice, and returns
// the callback query and the browser's state.
func (e *env) login(t *testing.T, choice string) (url.Values, string) {
	t.Helper()
	authURL, state, err := e.client.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if u, _ := url.Parse(authURL); u.Query().Get("code_challenge_method") != "S256" || u.Query().Get("nonce") == "" {
		t.Fatalf("authorization request without PKCE or nonce: %s", authURL)
	}
	resp, err := noFollow.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := reqRE.FindStringSubmatch(string(page))
	if m == nil {
		t.Fatalf("IdP login page: %d %s", resp.StatusCode, page)
	}
	form := url.Values{"req": {m[1]}}
	if choice != "" {
		form.Set("doctorid", choice)
	}
	resp, err = noFollow.PostForm(e.idp.URL+"/authorize", form)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	return loc.Query(), state
}

func (e *env) practitioner(t *testing.T, coll string, state adapter.State) store.Practitioner {
	t.Helper()
	ctx := context.Background()
	p, err := e.st.FindOrCreatePractitioner(ctx, store.Practitioner{FullName: "Laia Puig Soler", AdministrativeNumber: "11111111H", CollegiateNumber: coll})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	en := adapter.Enrollment{ID: "6a0d7f3c-2b1e-4e8a-9c55-1f0b2d3e4a5b", State: state, CollegiateNumber: coll, UpdatedAt: &now}
	if _, err := e.st.UpsertEnrollment(ctx, p.ID, en, []byte(`{}`), true); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoginGrantedBindsTheDoctorID(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	p := e.practitioner(t, "282810001", adapter.Completed)

	q, state := e.login(t, "282810001")
	if q.Get("iss") != e.idp.URL {
		t.Fatalf("callback without iss: %v", q)
	}
	id, err := e.client.Finish(ctx, q, state)
	if err != nil {
		t.Fatal(err)
	}
	if id.CollegiateNumber != "282810001" || id.GivenName != "LAIA" || id.ACR == "" || id.Subject == "" {
		t.Fatalf("identity = %+v", id)
	}
	d, err := doctorlogin.Decide(ctx, e.st, id)
	if err != nil || !d.Granted || d.Practitioner.ID != p.ID {
		t.Fatalf("decision = %+v, %v", d, err)
	}
	bound, _ := e.st.Practitioner(ctx, p.ID)
	if bound.DoctorIDSubject != id.Subject || bound.DoctorIDIssuer != e.idp.URL {
		t.Fatalf("binding = %q %q", bound.DoctorIDIssuer, bound.DoctorIDSubject)
	}

	// Same DoctorID again: granted. Another identity on the record: refused.
	q, state = e.login(t, "282810001")
	id, err = e.client.Finish(ctx, q, state)
	if err != nil {
		t.Fatal(err)
	}
	if d, _ := doctorlogin.Decide(ctx, e.st, id); !d.Granted {
		t.Fatalf("second login refused: %+v", d)
	}
	_ = e.st.ResetDoctorIDBinding(ctx, p.ID)
	_ = e.st.BindDoctorID(ctx, p.ID, e.idp.URL, "someone-else")
	if d, _ := doctorlogin.Decide(ctx, e.st, id); d.Granted || d.Reason != doctorlogin.ReasonIdentityMismatch {
		t.Fatalf("decision with another bound identity = %+v", d)
	}
}

func TestAccessRule(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name   string
		setup  func(*env, *testing.T)
		choice string
		reason string
	}{
		{"not a physician of the clinic", func(*env, *testing.T) {}, idpstub.Outsider.CollegiateNumber, doctorlogin.ReasonNotRegistered},
		{"enrolment not completed", func(e *env, t *testing.T) { e.practitioner(t, "282810001", adapter.PendingConfirmation) }, "282810001", doctorlogin.ReasonNotVerified},
		{"DoctorID invalidated", func(e *env, t *testing.T) {
			p := e.practitioner(t, "282810001", adapter.Completed)
			list, _ := e.st.EnrollmentsOf(ctx, p.ID)
			_ = e.st.MarkInvalidated(ctx, list[0].ID, "revoke", "", time.Now())
		}, "282810001", doctorlogin.ReasonInvalidated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			tc.setup(e, t)
			q, state := e.login(t, tc.choice)
			id, err := e.client.Finish(ctx, q, state)
			if err != nil {
				t.Fatal(err)
			}
			d, err := doctorlogin.Decide(ctx, e.st, id)
			if err != nil || d.Granted || d.Reason != tc.reason {
				t.Fatalf("decision = %+v, %v; want reason %s", d, err, tc.reason)
			}
		})
	}
}

func TestCallbackProtections(t *testing.T) {
	ctx := context.Background()

	t.Run("state from another browser", func(t *testing.T) {
		e := newEnv(t)
		q, _ := e.login(t, "282810001")
		if _, err := e.client.Finish(ctx, q, "attacker-state"); !errors.Is(err, doctorlogin.ErrStateMismatch) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("callback replayed", func(t *testing.T) {
		e := newEnv(t)
		q, state := e.login(t, "282810001")
		if _, err := e.client.Finish(ctx, q, state); err != nil {
			t.Fatal(err)
		}
		if _, err := e.client.Finish(ctx, q, state); !errors.Is(err, doctorlogin.ErrUnknownState) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("iss of another provider", func(t *testing.T) {
		e := newEnv(t)
		q, state := e.login(t, "282810001")
		q.Set("iss", "https://evil.example")
		if _, err := e.client.Finish(ctx, q, state); !errors.Is(err, doctorlogin.ErrIssuerMismatch) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("cancelled at the IdP", func(t *testing.T) {
		e := newEnv(t)
		q, state := e.login(t, "")
		var idpErr *doctorlogin.IdPError
		if _, err := e.client.Finish(ctx, q, state); !errors.As(err, &idpErr) || idpErr.Code != "access_denied" {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("assertion signed with another key", func(t *testing.T) {
		e := newEnv(t)
		q, state := e.login(t, "282810001")
		// Steal the code and redeem it with a client holding a different key.
		other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		thief, _ := doctorlogin.New(doctorlogin.Config{Issuer: e.idp.URL, ClientID: "vitalia",
			RedirectURL: "http://unused/profesional/callback", Scopes: []string{"openid"}, SigningKey: other})
		_, st2, _ := thief.Start(ctx)
		q.Set("state", st2)
		if _, err := thief.Finish(ctx, q, st2); err == nil || !strings.Contains(err.Error(), "invalid_client") {
			t.Fatalf("err = %v, want invalid_client", err)
		}
		_ = state
	})
}

func TestParseSigningKey(t *testing.T) {
	if _, err := doctorlogin.ParseSigningKey("not a key"); err == nil {
		t.Fatal("expected an error")
	}
}
