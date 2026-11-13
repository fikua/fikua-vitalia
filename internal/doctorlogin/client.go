// Package doctorlogin lets the clinic's physicians sign in with their
// DoctorID: the clinic is an OpenID Connect client (relying party) of the
// identity provider, with the Authorization Code Flow, PKCE S256 and
// private_key_jwt client authentication.
//
// The same relying party also signs in against the clinic's own identity
// provider (Authentik), which federates DoctorID for the physicians and
// holds the staff accounts. That one authenticates the clinic with a client
// secret (client_secret_basic) instead of private_key_jwt.
package doctorlogin

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	_ "crypto/sha256" // registers SHA-256 for the JWK thumbprint
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"
)

// Config of the relying party.
type Config struct {
	Issuer      string
	ClientID    string
	RedirectURL string
	Scopes      []string
	ACR         string            // optional eIDAS level, requested as essential
	SigningKey  *ecdsa.PrivateKey // private_key_jwt; or
	Secret      string            // client_secret_basic, when SigningKey is nil
	HTTP        *http.Client
	Now         func() time.Time
}

// Identity is what the ID Token says about the physician.
type Identity struct {
	Issuer           string
	Subject          string
	GivenName        string
	FamilyName       string
	CollegiateNumber string // personal_administrative_number: the registration number in DoctorID v1
	Name             string
	Username         string   // preferred_username
	Groups           []string // groups, as the clinic's identity provider sends them
	CredentialType   string
	ACR              string
	AMR              []string
	AuthTime         time.Time
	Claims           map[string]any
	RawClaims        string
	RawIDToken       string // kept to end the session at the provider (id_token_hint)
}

// Errors of the callback. An IdPError carries the error the IdP returned.
var (
	ErrStateMismatch  = errors.New("state does not match this browser's login")
	ErrUnknownState   = errors.New("login request unknown or expired")
	ErrIssuerMismatch = errors.New("iss parameter does not match the issuer")
	ErrNonceMismatch  = errors.New("nonce does not match")
	ErrNoIDToken      = errors.New("token response has no id_token")
)

// IdPError is an error response from the identity provider.
type IdPError struct{ Code, Description string }

func (e *IdPError) Error() string {
	return "identity provider answered " + e.Code + ": " + e.Description
}

// Client is the relying party.
type Client struct {
	cfg   Config
	keyID string

	mu       sync.Mutex
	provider *oidc.Provider
	pending  map[string]pendingLogin
}

type pendingLogin struct {
	nonce, verifier string
	expires         time.Time
}

const loginTTL = 10 * time.Minute

// New builds the client. Discovery happens on first use, so the clinic
// starts even when the identity provider is down.
func New(cfg Config) (*Client, error) {
	if cfg.Issuer == "" || cfg.ClientID == "" || cfg.RedirectURL == "" || (cfg.SigningKey == nil && cfg.Secret == "") {
		return nil, errors.New("doctorlogin: issuer, client id, redirect URL and a signing key or client secret are required")
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 15 * time.Second}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	c := &Client{cfg: cfg, pending: map[string]pendingLogin{}}
	if cfg.SigningKey != nil {
		jwk := jose.JSONWebKey{Key: &cfg.SigningKey.PublicKey}
		thumb, err := jwk.Thumbprint(crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("key thumbprint: %w", err)
		}
		c.keyID = base64.RawURLEncoding.EncodeToString(thumb)
	}
	return c, nil
}

// JWKS is the public key set the identity provider uses to check the
// clinic's client assertions; nil with client secret authentication.
func (c *Client) JWKS() []byte {
	if c.cfg.SigningKey == nil {
		return nil
	}
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: &c.cfg.SigningKey.PublicKey, KeyID: c.keyID, Algorithm: string(jose.ES256), Use: "sig",
	}}}
	b, _ := json.Marshal(set)
	return b
}

// Issuer is the configured issuer.
func (c *Client) Issuer() string { return c.cfg.Issuer }

func (c *Client) ctx(ctx context.Context) context.Context {
	return oidc.ClientContext(context.WithValue(ctx, oauth2.HTTPClient, c.cfg.HTTP), c.cfg.HTTP)
}

func (c *Client) discover(ctx context.Context) (*oidc.Provider, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.provider != nil {
		return c.provider, nil
	}
	p, err := oidc.NewProvider(c.ctx(ctx), c.cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discovery of %s: %w", c.cfg.Issuer, err)
	}
	c.provider = p
	return p, nil
}

func (c *Client) oauth(p *oidc.Provider) *oauth2.Config {
	ep := p.Endpoint()
	if c.cfg.SigningKey == nil {
		ep.AuthStyle = oauth2.AuthStyleInHeader // client_secret_basic
		return &oauth2.Config{ClientID: c.cfg.ClientID, ClientSecret: c.cfg.Secret, Endpoint: ep,
			RedirectURL: c.cfg.RedirectURL, Scopes: c.cfg.Scopes}
	}
	ep.AuthStyle = oauth2.AuthStyleInParams // client_id in the body, authenticated by the assertion
	return &oauth2.Config{ClientID: c.cfg.ClientID, Endpoint: ep, RedirectURL: c.cfg.RedirectURL, Scopes: c.cfg.Scopes}
}

// Start begins a login: it returns the authorization URL and the state,
// which the caller binds to the browser (cookie).
func (c *Client) Start(ctx context.Context) (authURL, state string, err error) {
	p, err := c.discover(ctx)
	if err != nil {
		return "", "", err
	}
	state, nonce, verifier := random(), random(), oauth2.GenerateVerifier()
	c.mu.Lock()
	now := c.cfg.Now()
	for k, v := range c.pending {
		if now.After(v.expires) {
			delete(c.pending, k)
		}
	}
	c.pending[state] = pendingLogin{nonce: nonce, verifier: verifier, expires: now.Add(loginTTL)}
	c.mu.Unlock()

	opts := []oauth2.AuthCodeOption{oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)}
	if c.cfg.ACR != "" {
		claims, _ := json.Marshal(map[string]any{"id_token": map[string]any{
			"acr": map[string]any{"essential": true, "values": []string{c.cfg.ACR}}}})
		opts = append(opts, oauth2.SetAuthURLParam("claims", string(claims)))
	}
	return c.oauth(p).AuthCodeURL(state, opts...), state, nil
}

// Finish handles the callback: it checks the response, redeems the code
// and verifies the ID Token. browserState is the state bound to the browser.
func (c *Client) Finish(ctx context.Context, q url.Values, browserState string) (Identity, error) {
	state := q.Get("state")
	c.mu.Lock()
	pl, ok := c.pending[state]
	delete(c.pending, state) // one use, whatever happens next
	c.mu.Unlock()

	if state == "" || browserState == "" || state != browserState {
		return Identity{}, ErrStateMismatch
	}
	if !ok || c.cfg.Now().After(pl.expires) {
		return Identity{}, ErrUnknownState
	}
	p, err := c.discover(ctx)
	if err != nil {
		return Identity{}, err
	}
	// RFC 9207: when the IdP sends iss, it must be our issuer (mix-up defence).
	if iss := q.Get("iss"); iss != "" && iss != c.issuerOf(p) {
		return Identity{}, ErrIssuerMismatch
	}
	if code := q.Get("error"); code != "" {
		return Identity{}, &IdPError{Code: code, Description: q.Get("error_description")}
	}

	opts := []oauth2.AuthCodeOption{oauth2.VerifierOption(pl.verifier)}
	if c.cfg.SigningKey != nil {
		assertion, err := c.assertion(p.Endpoint().TokenURL)
		if err != nil {
			return Identity{}, err
		}
		opts = append(opts,
			oauth2.SetAuthURLParam("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
			oauth2.SetAuthURLParam("client_assertion", assertion))
	}
	tok, err := c.oauth(p).Exchange(c.ctx(ctx), q.Get("code"), opts...)
	if err != nil {
		return Identity{}, fmt.Errorf("code exchange: %w", err)
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return Identity{}, ErrNoIDToken
	}
	idt, err := p.VerifierContext(c.ctx(ctx), &oidc.Config{ClientID: c.cfg.ClientID, Now: c.cfg.Now}).Verify(c.ctx(ctx), raw)
	if err != nil {
		return Identity{}, fmt.Errorf("id token: %w", err)
	}
	if idt.Nonce != pl.nonce {
		return Identity{}, ErrNonceMismatch
	}
	id, err := identityOf(idt)
	id.RawIDToken = raw
	return id, err
}

// LogoutURL is where to send the browser to end the session at the
// identity provider too (OIDC RP-Initiated Logout): its end_session_endpoint
// with the ID Token as hint and the address to come back to. It returns ""
// when the provider has no such endpoint.
func (c *Client) LogoutURL(ctx context.Context, idTokenHint, postLogoutRedirect string) (string, error) {
	p, err := c.discover(ctx)
	if err != nil {
		return "", err
	}
	var meta struct {
		EndSession string `json:"end_session_endpoint"`
	}
	if err := p.Claims(&meta); err != nil || meta.EndSession == "" {
		return "", nil
	}
	u, err := url.Parse(meta.EndSession)
	if err != nil {
		return "", fmt.Errorf("end_session_endpoint: %w", err)
	}
	q := u.Query()
	q.Set("client_id", c.cfg.ClientID)
	if idTokenHint != "" {
		q.Set("id_token_hint", idTokenHint)
		if postLogoutRedirect != "" { // the spec ties the redirect to the hint
			q.Set("post_logout_redirect_uri", postLogoutRedirect)
		}
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (c *Client) issuerOf(p *oidc.Provider) string {
	var meta struct {
		Issuer string `json:"issuer"`
	}
	if err := p.Claims(&meta); err == nil && meta.Issuer != "" {
		return meta.Issuer
	}
	return c.cfg.Issuer
}

// assertion is the private_key_jwt client assertion (RFC 7523), audience
// the token endpoint.
func (c *Client) assertion(tokenURL string) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: c.cfg.SigningKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", c.keyID))
	if err != nil {
		return "", fmt.Errorf("assertion signer: %w", err)
	}
	now := c.cfg.Now()
	return jwt.Signed(signer).Claims(jwt.Claims{
		Issuer: c.cfg.ClientID, Subject: c.cfg.ClientID, Audience: jwt.Audience{tokenURL}, ID: random(),
		IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(time.Minute)),
	}).Serialize()
}

func identityOf(idt *oidc.IDToken) (Identity, error) {
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		return Identity{}, fmt.Errorf("id token claims: %w", err)
	}
	str := func(k string) string { s, _ := claims[k].(string); return s }
	id := Identity{
		Issuer: idt.Issuer, Subject: idt.Subject, GivenName: str("given_name"), FamilyName: str("family_name"),
		CollegiateNumber: str("personal_administrative_number"), CredentialType: str("credential_type"),
		Name: str("name"), Username: str("preferred_username"), ACR: str("acr"), Claims: claims,
	}
	if gs, ok := claims["groups"].([]any); ok {
		for _, g := range gs {
			if s, ok := g.(string); ok {
				id.Groups = append(id.Groups, s)
			}
		}
	}
	switch amr := claims["amr"].(type) {
	case []any:
		for _, v := range amr {
			if s, ok := v.(string); ok {
				id.AMR = append(id.AMR, s)
			}
		}
	case string:
		id.AMR = []string{amr}
	}
	if at, ok := claims["auth_time"].(float64); ok {
		id.AuthTime = time.Unix(int64(at), 0)
	}
	b, _ := json.MarshalIndent(claims, "", "  ")
	id.RawClaims = string(b)
	return id, nil
}

// ParseSigningKey reads an EC P-256 private key in PEM or base64 PKCS#8 DER.
func ParseSigningKey(s string) (*ecdsa.PrivateKey, error) {
	s = strings.TrimSpace(s)
	var der []byte
	if strings.Contains(s, "-----BEGIN") {
		block, _ := pem.Decode([]byte(s))
		if block == nil {
			return nil, errors.New("signing key: invalid PEM")
		}
		der = block.Bytes
	} else {
		var err error
		if der, err = base64.StdEncoding.DecodeString(s); err != nil {
			return nil, errors.New("signing key: not PEM nor base64")
		}
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		if ec, err2 := x509.ParseECPrivateKey(der); err2 == nil {
			key = ec
		} else {
			return nil, errors.New("signing key: not a PKCS#8 or SEC1 private key")
		}
	}
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("signing key: must be an EC P-256 key")
	}
	return ec, nil
}

func random() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
