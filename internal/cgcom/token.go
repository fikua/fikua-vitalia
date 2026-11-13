package cgcom

// The access token for the enrolment API, obtained with the platform
// credential by private_key_jwt (RFC 7523): the clinic signs a short-lived
// client assertion with its private key and exchanges it at the token
// endpoint (client_credentials grant, RFC 6749 section 4.4).
//
// What CGCOM's guide may still fix is configurable: the token endpoint, the
// assertion audience and the scope.

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// TokenConfig configures the private_key_jwt token source.
type TokenConfig struct {
	TokenURL string            // token endpoint
	ClientID string            // the platform credential CGCOM delivers
	Key      *ecdsa.PrivateKey // the platform's private key
	Audience string            // assertion audience; the token endpoint when empty
	Scope    string            // optional
	HTTP     *http.Client
	Now      func() time.Time
}

// TokenError is an error response from the token endpoint (RFC 6749 5.2).
type TokenError struct {
	Status      int
	Code        string
	Description string
}

func (e *TokenError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("token endpoint answered HTTP %d", e.Status)
	}
	return fmt.Sprintf("token endpoint answered HTTP %d %s: %s", e.Status, e.Code, e.Description)
}

// PrivateKeyJWTSource is a TokenSource that keeps the access token until
// shortly before it expires.
type PrivateKeyJWTSource struct {
	cfg    TokenConfig
	signer jose.Signer

	mu      sync.Mutex
	token   string
	expires time.Time
}

// renewBefore is how long before expiry a cached token is replaced.
const renewBefore = 30 * time.Second

// NewPrivateKeyJWTSource checks the configuration and prepares the signer.
func NewPrivateKeyJWTSource(cfg TokenConfig) (*PrivateKeyJWTSource, error) {
	if cfg.TokenURL == "" || cfg.ClientID == "" || cfg.Key == nil {
		return nil, errors.New("cgcom token: token URL, client id and private key are required")
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 15 * time.Second}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Audience == "" {
		cfg.Audience = cfg.TokenURL
	}
	kid, err := KeyThumbprint(&cfg.Key.PublicKey)
	if err != nil {
		return nil, err
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: cfg.Key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid))
	if err != nil {
		return nil, fmt.Errorf("cgcom token: signer: %w", err)
	}
	return &PrivateKeyJWTSource{cfg: cfg, signer: signer}, nil
}

// Token returns a valid access token, asking for a new one when needed.
func (s *PrivateKeyJWTSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token != "" && s.cfg.Now().Before(s.expires.Add(-renewBefore)) {
		return s.token, nil
	}
	tok, ttl, err := s.fetch(ctx)
	if err != nil {
		return "", err
	}
	s.token, s.expires = tok, s.cfg.Now().Add(ttl)
	return s.token, nil
}

// Invalidate forgets the cached token: the API refused it.
func (s *PrivateKeyJWTSource) Invalidate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.token = ""
}

// Assertion signs a client assertion (RFC 7523 section 3).
func (s *PrivateKeyJWTSource) Assertion() (string, error) {
	now := s.cfg.Now()
	var jti [16]byte
	_, _ = rand.Read(jti[:])
	return jwt.Signed(s.signer).Claims(jwt.Claims{
		Issuer: s.cfg.ClientID, Subject: s.cfg.ClientID, Audience: jwt.Audience{s.cfg.Audience},
		ID: base64.RawURLEncoding.EncodeToString(jti[:]), IssuedAt: jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(time.Minute)),
	}).Serialize()
}

func (s *PrivateKeyJWTSource) fetch(ctx context.Context) (string, time.Duration, error) {
	assertion, err := s.Assertion()
	if err != nil {
		return "", 0, fmt.Errorf("cgcom token: assertion: %w", err)
	}
	form := url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {s.cfg.ClientID},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
	}
	if s.cfg.Scope != "" {
		form.Set("scope", s.cfg.Scope)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := s.cfg.HTTP.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("cgcom token: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var body struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	_ = json.Unmarshal(raw, &body)
	if resp.StatusCode != http.StatusOK {
		return "", 0, &TokenError{Status: resp.StatusCode, Code: body.Error, Description: body.Description}
	}
	if body.AccessToken == "" || (body.TokenType != "" && !strings.EqualFold(body.TokenType, "Bearer")) {
		return "", 0, errors.New("cgcom token: response without a bearer access_token")
	}
	ttl := time.Duration(body.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = 5 * time.Minute // no expires_in: assume a short life
	}
	return body.AccessToken, ttl, nil
}
