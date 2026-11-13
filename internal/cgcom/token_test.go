package cgcom_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/fikua/fikua-vitalia/internal/cgcom"
)

func TestPublicJWKHasExactlyTheFourMembers(t *testing.T) {
	key, err := cgcom.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := cgcom.PublicJWK(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if len(m) != 4 || m["kty"] != "EC" || m["crv"] != "P-256" || len(m["x"]) != 43 || len(m["y"]) != 43 {
		t.Fatalf("jwk = %s", raw)
	}
	// A JOSE library reads it as this same public key.
	var jwk jose.JSONWebKey
	if err := jwk.UnmarshalJSON(raw); err != nil || !jwk.Valid() || !jwk.IsPublic() {
		t.Fatalf("not a valid public JWK: %v", err)
	}
	if !jwk.Key.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
		t.Fatal("the JWK is not the key's public half")
	}

	enc, err := cgcom.EncodePrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	back, err := cgcom.ParsePrivateKey(enc)
	if err != nil || !back.Equal(key) {
		t.Fatalf("private key round trip: %v", err)
	}
	if _, err := cgcom.ParsePrivateKey("not a key"); err == nil {
		t.Fatal("garbage accepted as a key")
	}
}

// tokenServer is a token endpoint that checks each client assertion with
// the registered public key.
type tokenServer struct {
	*httptest.Server
	mu    sync.Mutex
	calls int
	ttl   int
	fail  bool
}

func newTokenServer(t *testing.T, clientID string, key *ecdsa.PrivateKey) *tokenServer {
	t.Helper()
	ts := &tokenServer{ttl: 300}
	ts.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts.mu.Lock()
		ts.calls++
		n, fail, ttl := ts.calls, ts.fail, ts.ttl
		ts.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if fail {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"unknown key"}`))
			return
		}
		_ = r.ParseForm()
		f := r.PostForm
		if f.Get("grant_type") != "client_credentials" || f.Get("client_id") != clientID ||
			f.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
			t.Errorf("token request form = %v", f)
		}
		tok, err := jwt.ParseSigned(f.Get("client_assertion"), []jose.SignatureAlgorithm{jose.ES256})
		if err != nil {
			t.Errorf("assertion: %v", err)
			return
		}
		if h := tok.Headers[0].JSONWebKey; h == nil || !h.IsPublic() || !h.Key.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
			t.Errorf("assertion header jwk = %+v, want the platform public key", h)
		}
		var c jwt.Claims
		if err := tok.Claims(&key.PublicKey, &c); err != nil {
			t.Errorf("assertion signature: %v", err)
			return
		}
		want := jwt.Expected{Issuer: clientID, Subject: clientID, AnyAudience: jwt.Audience{"http://" + r.Host + "/token"}, Time: c0(tok, key)}
		if err := c.Validate(want); err != nil || c.ID == "" || c.Expiry.Time().Sub(c.IssuedAt.Time()) > 2*time.Minute {
			t.Errorf("assertion claims %+v: %v", c, err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": fmt.Sprintf("tok-%d", n), "token_type": "Bearer", "expires_in": ttl})
	}))
	t.Cleanup(ts.Close)
	return ts
}

func TestPrivateKeyJWTTokenIsCachedAndRenewed(t *testing.T) {
	key, _ := cgcom.GenerateKey()
	ts := newTokenServer(t, "vitalia-platform", key)
	now := time.Now()
	src, err := cgcom.NewPrivateKeyJWTSource(cgcom.TokenConfig{TokenURL: ts.URL + "/token", ClientID: "vitalia-platform", Key: key,
		Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	a, err := src.Token(ctx)
	if err != nil || a != "tok-1" {
		t.Fatalf("first token = %q, %v", a, err)
	}
	if b, _ := src.Token(ctx); b != "tok-1" || ts.calls != 1 {
		t.Fatalf("cached token = %q after %d calls", b, ts.calls)
	}
	now = now.Add(290 * time.Second) // within the last 30 s of its life
	if c, _ := src.Token(ctx); c != "tok-2" {
		t.Fatalf("renewed token = %q", c)
	}
	src.Invalidate()
	if d, _ := src.Token(ctx); d != "tok-3" {
		t.Fatalf("token after invalidate = %q", d)
	}

	ts.mu.Lock()
	ts.fail = true
	ts.mu.Unlock()
	src.Invalidate()
	_, err = src.Token(ctx)
	var te *cgcom.TokenError
	if !errors.As(err, &te) || te.Status != http.StatusUnauthorized || te.Code != "invalid_client" {
		t.Fatalf("token error = %v", err)
	}
}

// A token the API refuses is replaced once, transparently.
func TestClientRetriesOnceWithANewTokenAfter401(t *testing.T) {
	key, _ := cgcom.GenerateKey()
	ts := newTokenServer(t, "vitalia-platform", key)
	var mu sync.Mutex
	var seen []string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Authorization"))
		mu.Unlock()
		if r.Header.Get("Authorization") == "Bearer tok-1" { // e.g. revoked
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"type":"invalid_token","status":401}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"6a0d7f3c-2b1e-4e8a-9c55-1f0b2d3e4a5b","state":"INITIATED","collegiate_number":"282810001"}`))
	}))
	t.Cleanup(api.Close)

	src, err := cgcom.NewPrivateKeyJWTSource(cgcom.TokenConfig{TokenURL: ts.URL + "/token", ClientID: "vitalia-platform", Key: key})
	if err != nil {
		t.Fatal(err)
	}
	base, _ := url.Parse(api.URL)
	client := cgcom.NewClient(base, http.DefaultClient, src, nil)
	res, err := client.GetEnrollment(context.Background(), "6a0d7f3c-2b1e-4e8a-9c55-1f0b2d3e4a5b")
	if err != nil || res.Enrollment.State != cgcom.Initiated {
		t.Fatalf("get = %+v, %v", res, err)
	}
	if len(seen) != 2 || seen[0] != "Bearer tok-1" || seen[1] != "Bearer tok-2" {
		t.Fatalf("authorizations = %v", seen)
	}
}

// c0 is the assertion's issue time: tests drive the client with a fake clock.
func c0(tok *jwt.JSONWebToken, key *ecdsa.PrivateKey) time.Time {
	var c jwt.Claims
	_ = tok.Claims(&key.PublicKey, &c)
	return c.IssuedAt.Time()
}

// syntheticCredential is an SD-JWT shaped like the LEARCredentialMachine,
// bound (cnf.jwk) to pub. Only the binding matters to the client.
func syntheticCredential(t *testing.T, pub *ecdsa.PublicKey) string {
	t.Helper()
	issuer, _ := cgcom.GenerateKey()
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: issuer}, (&jose.SignerOptions{}).WithType("dc+sd-jwt"))
	raw, _ := cgcom.PublicJWK(pub)
	var cnf map[string]any
	_ = json.Unmarshal(raw, &cnf)
	jws, err := jwt.Signed(signer).Claims(map[string]any{"iss": "VATES-A15456585", "vct": "learcredential.machine.sd.1",
		"cnf": map[string]any{"jwk": cnf}}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return jws + "~WyJzYWx0IiwibWFuZGF0ZWUiLHt9XQ~"
}

func TestAssertionCarriesThePresentationOfTheCredential(t *testing.T) {
	key, _ := cgcom.GenerateKey()
	did, _ := cgcom.DIDKey(&key.PublicKey)
	cred := syntheticCredential(t, &key.PublicKey)

	var got url.Values
	var tenant string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		got, tenant = r.PostForm, r.Header.Get("X-Tenant")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"m2m","token_type":"Bearer","expires_in":600}`))
	}))
	t.Cleanup(srv.Close)

	src, err := cgcom.NewPrivateKeyJWTSource(cgcom.TokenConfig{TokenURL: srv.URL + "/oidc/token", Key: key, Credential: cred,
		Audience: "https://verifier.example.test", Tenant: "cgcom"})
	if err != nil {
		t.Fatal(err)
	}
	if tok, err := src.Token(context.Background()); err != nil || tok != "m2m" {
		t.Fatalf("token = %q, %v", tok, err)
	}
	if tenant != "cgcom" || got.Get("client_id") != did || got.Get("scope") != "" {
		t.Fatalf("request: tenant %q, form %v", tenant, got)
	}

	// The assertion: iss = sub = did:key, aud = the Verifier, vp_token = base64(VP-JWT).
	assertion, _ := jwt.ParseSigned(got.Get("client_assertion"), []jose.SignatureAlgorithm{jose.ES256})
	var claims struct {
		jwt.Claims
		VPToken string `json:"vp_token"`
	}
	if err := assertion.Claims(&key.PublicKey, &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != did || claims.Subject != did || !claims.Audience.Contains("https://verifier.example.test") ||
		claims.Expiry.Time().Sub(claims.IssuedAt.Time()) != 120*time.Second {
		t.Fatalf("assertion claims = %+v", claims.Claims)
	}
	vpRaw, err := base64.StdEncoding.DecodeString(claims.VPToken)
	if err != nil {
		t.Fatalf("vp_token is not standard base64: %v", err)
	}
	vp, err := jwt.ParseSigned(string(vpRaw), []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	var vpc struct {
		jwt.Claims
		VP struct {
			Context []string `json:"@context"`
			Type    []string `json:"type"`
			VCs     []string `json:"verifiableCredential"`
		} `json:"vp"`
	}
	if err := vp.Claims(&key.PublicKey, &vpc); err != nil {
		t.Fatal(err)
	}
	if vpc.Issuer != did || len(vpc.VP.VCs) != 1 || vpc.VP.VCs[0] != cred || vpc.VP.Type[0] != "VerifiablePresentation" ||
		vp.Headers[0].JSONWebKey == nil {
		t.Fatalf("vp = %+v", vpc)
	}

	// A credential bound to another key, or a client id that is not the key's: refused at start.
	other, _ := cgcom.GenerateKey()
	if _, err := cgcom.NewPrivateKeyJWTSource(cgcom.TokenConfig{TokenURL: srv.URL, Key: key, Credential: syntheticCredential(t, &other.PublicKey)}); err == nil {
		t.Fatal("credential of another key accepted")
	}
	if _, err := cgcom.NewPrivateKeyJWTSource(cgcom.TokenConfig{TokenURL: srv.URL, Key: key, Credential: cred, ClientID: "did:key:zOther"}); err == nil {
		t.Fatal("foreign client id accepted")
	}
}
