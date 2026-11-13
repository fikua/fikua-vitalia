package cgcom

// The access token for the enrolment API, obtained with the platform
// credential by private_key_jwt (RFC 7523), as the EUDIStack Verifier
// expects it (same as its Java M2M SDK):
//
//   - a VP-JWT signed with the platform key, holding the platform credential
//     (LEARCredentialMachine) in vp.verifiableCredential;
//   - a client assertion signed with the same key: iss = sub = client_id
//     (the key's did:key), aud = the Verifier, 120 s of life, and the VP-JWT
//     in standard base64 in the vp_token claim;
//   - both with the public key in the JWS header (jwk);
//   - a client_credentials request to the token endpoint, with the tenant in
//     the X-Tenant header.

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
	TokenURL   string            // token endpoint
	Key        *ecdsa.PrivateKey // the platform's private key
	Credential string            // the platform credential (SD-JWT or JWT) CGCOM delivers; empty sends no vp_token
	ClientID   string            // the key's did:key when empty
	Audience   string            // assertion audience; the token endpoint when empty
	Tenant     string            // X-Tenant header; none when empty
	Scope      string            // optional
	HTTP       *http.Client
	Now        func() time.Time
}

// TokenError is an error response from the token endpoint (RFC 6749 5.2).
type TokenError struct {
	Status      int
	Code        string
	Description string
	Body        string // the raw response, cut, for diagnosis
}

func (e *TokenError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("token endpoint answered HTTP %d: %s", e.Status, e.Body)
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
	if cfg.TokenURL == "" || cfg.Key == nil {
		return nil, errors.New("cgcom token: token URL and private key are required")
	}
	did, err := DIDKey(&cfg.Key.PublicKey)
	if err != nil {
		return nil, err
	}
	if cfg.ClientID == "" {
		cfg.ClientID = did
	}
	if cfg.Credential != "" {
		// Fail at start, not at the first enrolment: the credential must be
		// bound to this key and name this client.
		if err := checkCredential(cfg.Credential, &cfg.Key.PublicKey); err != nil {
			return nil, err
		}
		if cfg.ClientID != did {
			return nil, fmt.Errorf("cgcom token: client id %s is not the key's did:key %s", cfg.ClientID, did)
		}
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
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: cfg.Key},
		(&jose.SignerOptions{EmbedJWK: true}).WithType("JWT"))
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

// Lifetimes of the presentation and of the assertion (as the Java SDK).
const (
	vpLifetime        = 300 * time.Second
	assertionLifetime = 120 * time.Second
)

// Assertion signs a client assertion (RFC 7523 section 3) carrying the
// presentation of the platform credential.
func (s *PrivateKeyJWTSource) Assertion() (string, error) {
	now := s.cfg.Now()
	claims := jwt.Claims{
		Issuer: s.cfg.ClientID, Subject: s.cfg.ClientID, Audience: jwt.Audience{s.cfg.Audience},
		ID: newJTI(), IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(assertionLifetime)),
	}
	builder := jwt.Signed(s.signer).Claims(claims)
	if s.cfg.Credential != "" {
		vp, err := s.presentation(now)
		if err != nil {
			return "", err
		}
		builder = builder.Claims(map[string]any{"vp_token": base64.StdEncoding.EncodeToString([]byte(vp))})
	}
	return builder.Serialize()
}

// presentation is the VP-JWT of the platform credential.
func (s *PrivateKeyJWTSource) presentation(now time.Time) (string, error) {
	return jwt.Signed(s.signer).Claims(jwt.Claims{
		Issuer: s.cfg.ClientID, Subject: s.cfg.ClientID, ID: newJTI(),
		IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(vpLifetime)),
	}).Claims(map[string]any{"vp": map[string]any{
		"@context":             []string{"https://www.w3.org/2018/credentials/v1"},
		"type":                 []string{"VerifiablePresentation"},
		"verifiableCredential": []string{s.cfg.Credential},
	}}).Serialize()
}

func newJTI() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6], b[8] = b[6]&0x0f|0x40, b[8]&0x3f|0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// checkCredential verifies that the credential's confirmation key (cnf.jwk)
// is the platform key. It reads the issuer-signed part only; the signature
// is the Verifier's business.
func checkCredential(credential string, pub *ecdsa.PublicKey) error {
	jws := strings.SplitN(credential, "~", 2)[0]
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return errors.New("cgcom token: the platform credential is not a JWT or SD-JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return errors.New("cgcom token: the platform credential payload is not base64url")
	}
	var body struct {
		Cnf struct {
			JWK json.RawMessage `json:"jwk"`
		} `json:"cnf"`
	}
	if err := json.Unmarshal(payload, &body); err != nil || len(body.Cnf.JWK) == 0 {
		return errors.New("cgcom token: the platform credential has no cnf.jwk")
	}
	var jwk jose.JSONWebKey
	if err := jwk.UnmarshalJSON(body.Cnf.JWK); err != nil {
		return fmt.Errorf("cgcom token: cnf.jwk: %w", err)
	}
	if k, ok := jwk.Key.(*ecdsa.PublicKey); !ok || !k.Equal(pub) {
		return errors.New("cgcom token: the platform credential is bound to another key")
	}
	return nil
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
	if s.cfg.Tenant != "" {
		req.Header.Set("X-Tenant", s.cfg.Tenant)
	}
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
		cut := string(raw)
		if len(cut) > 500 {
			cut = cut[:500] + "…"
		}
		return "", 0, &TokenError{Status: resp.StatusCode, Code: body.Error, Description: body.Description, Body: cut}
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
