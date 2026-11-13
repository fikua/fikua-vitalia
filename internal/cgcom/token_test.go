package cgcom_test

import (
	"context"
	"crypto/ecdsa"
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
	kid, _ := cgcom.KeyThumbprint(&key.PublicKey)
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
		if tok.Headers[0].KeyID != kid {
			t.Errorf("assertion kid = %q, want the key thumbprint", tok.Headers[0].KeyID)
		}
		var c jwt.Claims
		if err := tok.Claims(&key.PublicKey, &c); err != nil {
			t.Errorf("assertion signature: %v", err)
			return
		}
		want := jwt.Expected{Issuer: clientID, Subject: clientID, AnyAudience: jwt.Audience{"http://" + r.Host + "/token"}, Time: c0(tok, key)}
		if err := c.Validate(want); err != nil || c.ID == "" || c.Expiry.Time().Sub(c.IssuedAt.Time()) > time.Minute {
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
