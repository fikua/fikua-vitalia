// Package idpstub is a stand-in of the DoctorID identity provider (an
// OpenID Provider in front of the wallet), written from the EUD-296 model:
// Authorization Code Flow with PKCE S256, private_key_jwt client
// authentication and an ES256 ID Token with the DoctorID attributes. Its
// login page replaces the wallet: the person picks which DoctorID to present.
//
// Besides the clinic, it can register clients that authenticate with a
// client secret (client_secret_basic or client_secret_post): that is how a
// workforce identity provider such as Authentik federates it.
//
// For tests and demos only.
package idpstub

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Client is a registered relying party. It authenticates with
// private_key_jwt (JWKSURL) or, when Secret is set, with that client secret.
type Client struct {
	ID          string
	RedirectURI string
	JWKSURL     string // where the IdP fetches the client's public keys
	Secret      string // client_secret_basic / client_secret_post instead of private_key_jwt
}

// Holder is a DoctorID the simulated wallet can present.
type Holder struct {
	CollegiateNumber string
	GivenName        string
	FamilyName       string
	Data             map[string]any
	Note             string
}

// IdP is the simulated OpenID Provider.
type IdP struct {
	Issuer  string
	Client  Client   // the clinic
	Extra   []Client // more relying parties, e.g. a federating identity provider
	Holders func() []Holder
	HTTP    *http.Client
	Now     func() time.Time
	Key     *ecdsa.PrivateKey // ID Token signing key; generated when nil

	once  sync.Once
	key   *ecdsa.PrivateKey
	kid   string
	mu    sync.Mutex
	reqs  map[string]authRequest
	codes map[string]grant
	jtis  map[string]time.Time
}

type authRequest struct {
	Client                         Client
	State, Nonce, Challenge, Scope string
	expires                        time.Time
}

type grant struct {
	authRequest
	holder  Holder
	authAt  time.Time
	expires time.Time
}

// Outsider is a physician with a DoctorID who does not work at the clinic.
var Outsider = Holder{CollegiateNumber: "289999990", GivenName: "MARTA", FamilyName: "SOLER GIL",
	Note: "Médica con DoctorID que no trabaja en la clínica",
	Data: map[string]any{"medical_board": []string{"Colegio Oficial de Médicos de Girona"}, "medical_speciality": []string{"Neurología"}, "legally_entitled": true}}

func (p *IdP) init() {
	p.once.Do(func() {
		p.key = p.Key
		if p.key == nil {
			p.key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		}
		thumb, _ := (&jose.JSONWebKey{Key: &p.key.PublicKey}).Thumbprint(crypto.SHA256)
		p.kid = base64.RawURLEncoding.EncodeToString(thumb)
		p.reqs, p.codes, p.jtis = map[string]authRequest{}, map[string]grant{}, map[string]time.Time{}
		if p.HTTP == nil {
			p.HTTP = &http.Client{Timeout: 10 * time.Second}
		}
		if p.Now == nil {
			p.Now = time.Now
		}
	})
}

// Handler serves discovery, JWKS, the login page and the token endpoint.
func (p *IdP) Handler() http.Handler {
	p.init()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /jwks", p.jwks)
	mux.HandleFunc("GET /authorize", p.authorize)
	mux.HandleFunc("POST /authorize", p.decide)
	mux.HandleFunc("POST /token", p.token)
	return mux
}

// client returns the registered client with that id.
func (p *IdP) client(id string) (Client, bool) {
	for _, c := range append([]Client{p.Client}, p.Extra...) {
		if c.ID != "" && c.ID == id {
			return c, true
		}
	}
	return Client{}, false
}

func (p *IdP) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                         p.Issuer,
		"authorization_endpoint":                         p.Issuer + "/authorize",
		"token_endpoint":                                 p.Issuer + "/token",
		"jwks_uri":                                       p.Issuer + "/jwks",
		"response_types_supported":                       []string{"code"},
		"grant_types_supported":                          []string{"authorization_code"},
		"subject_types_supported":                        []string{"public"},
		"id_token_signing_alg_values_supported":          []string{"ES256"},
		"token_endpoint_auth_methods_supported":          []string{"private_key_jwt", "client_secret_basic", "client_secret_post"},
		"code_challenge_methods_supported":               []string{"S256"},
		"scopes_supported":                               []string{"openid", "profile", "doctorid"},
		"acr_values_supported":                           []string{"http://eidas.europa.eu/LoA/high"},
		"authorization_response_iss_parameter_supported": true,
	})
}

func (p *IdP) jwks(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &p.key.PublicKey, KeyID: p.kid, Algorithm: "ES256", Use: "sig"}}})
}

func (p *IdP) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	// Errors about the client or its redirect URI are shown here and never
	// redirected (OIDC Core 3.1.2.6).
	client, ok := p.client(q.Get("client_id"))
	if !ok || q.Get("redirect_uri") != client.RedirectURI {
		http.Error(w, "Unknown client or redirect URI", http.StatusBadRequest)
		return
	}
	scopes := strings.Fields(q.Get("scope"))
	switch {
	case q.Get("response_type") != "code", !slices.Contains(scopes, "openid"):
		p.redirectError(w, r, client, q.Get("state"), "invalid_request", "response_type code and scope openid are required")
		return
	case q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256":
		p.redirectError(w, r, client, q.Get("state"), "invalid_request", "PKCE S256 is required")
		return
	case q.Get("nonce") == "" && client.Secret == "": // the clinic always sends one; a federating IdP may not
		p.redirectError(w, r, client, q.Get("state"), "invalid_request", "nonce is required")
		return
	}
	id := randomID()
	p.mu.Lock()
	p.reqs[id] = authRequest{Client: client, State: q.Get("state"), Nonce: q.Get("nonce"), Challenge: q.Get("code_challenge"),
		Scope: q.Get("scope"), expires: p.Now().Add(5 * time.Minute)}
	p.mu.Unlock()

	holders := append(p.Holders(), Outsider)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = loginPage.Execute(w, map[string]any{"Req": id, "Holders": holders, "Client": client.ID})
}

func (p *IdP) decide(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	req, ok := p.reqs[r.PostFormValue("req")]
	delete(p.reqs, r.PostFormValue("req"))
	p.mu.Unlock()
	if !ok || p.Now().After(req.expires) {
		http.Error(w, "La petición de inicio de sesión ha caducado. Vuelve a la aplicación.", http.StatusBadRequest)
		return
	}
	choice := r.PostFormValue("doctorid")
	if choice == "" {
		p.redirectError(w, r, req.Client, req.State, "access_denied", "")
		return
	}
	var holder *Holder
	for _, h := range append(p.Holders(), Outsider) {
		if h.CollegiateNumber == choice {
			holder = &h
			break
		}
	}
	if holder == nil {
		p.redirectError(w, r, req.Client, req.State, "access_denied", "")
		return
	}
	code := randomID()
	p.mu.Lock()
	p.codes[code] = grant{authRequest: req, holder: *holder, authAt: p.Now(), expires: p.Now().Add(time.Minute)}
	p.mu.Unlock()
	p.redirect(w, r, req.Client, url.Values{"code": {code}, "state": {req.State}})
}

func (p *IdP) redirectError(w http.ResponseWriter, r *http.Request, c Client, state, code, desc string) {
	v := url.Values{"error": {code}, "state": {state}}
	if desc != "" {
		v.Set("error_description", desc)
	}
	p.redirect(w, r, c, v)
}

func (p *IdP) redirect(w http.ResponseWriter, r *http.Request, c Client, v url.Values) {
	v.Set("iss", p.Issuer) // RFC 9207
	http.Redirect(w, r, c.RedirectURI+"?"+v.Encode(), http.StatusFound)
}

func (p *IdP) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || r.PostForm.Get("grant_type") != "authorization_code" {
		tokenError(w, "unsupported_grant_type")
		return
	}
	f := r.PostForm
	client, err := p.authenticate(r, f)
	if err != nil {
		w.Header().Set("WWW-Authenticate", "private_key_jwt")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client", "error_description": err.Error()})
		return
	}
	p.mu.Lock()
	g, ok := p.codes[f.Get("code")]
	delete(p.codes, f.Get("code"))
	p.mu.Unlock()
	if !ok || p.Now().After(g.expires) || g.Client.ID != client.ID || f.Get("redirect_uri") != client.RedirectURI {
		tokenError(w, "invalid_grant")
		return
	}
	sum := sha256.Sum256([]byte(f.Get("code_verifier")))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != g.Challenge {
		tokenError(w, "invalid_grant")
		return
	}
	idToken, err := p.idToken(g)
	if err != nil {
		http.Error(w, "signing failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"access_token": randomID(), "token_type": "Bearer", "expires_in": 300,
		"id_token": idToken, "scope": g.Scope})
}

// authenticate identifies the client at the token endpoint: by its client
// secret (HTTP Basic or form) or by its private_key_jwt assertion.
func (p *IdP) authenticate(r *http.Request, f url.Values) (Client, error) {
	if f.Get("client_assertion") == "" {
		id, secret, basic := r.BasicAuth()
		if !basic {
			id, secret = f.Get("client_id"), f.Get("client_secret")
		}
		c, ok := p.client(id)
		if !ok || c.Secret == "" || secret == "" ||
			subtle.ConstantTimeCompare([]byte(secret), []byte(c.Secret)) != 1 {
			return Client{}, fmt.Errorf("unknown client or wrong client secret")
		}
		return c, nil
	}
	if f.Get("client_id") != "" && f.Get("client_id") != p.Client.ID {
		return Client{}, fmt.Errorf("client_id does not match the assertion")
	}
	return p.Client, p.checkAssertion(r, f)
}

// checkAssertion verifies the clinic's private_key_jwt client assertion
// against its published keys.
func (p *IdP) checkAssertion(r *http.Request, f url.Values) error {
	if f.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		return fmt.Errorf("client_assertion_type is required")
	}
	tok, err := jwt.ParseSigned(f.Get("client_assertion"), []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return fmt.Errorf("client_assertion is not a valid JWS")
	}
	resp, err := p.HTTP.Get(p.Client.JWKSURL)
	if err != nil {
		return fmt.Errorf("client JWKS unreachable")
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(raw, &set); err != nil || len(set.Keys) == 0 {
		return fmt.Errorf("client JWKS invalid")
	}
	key := set.Keys[0]
	if len(tok.Headers) > 0 && tok.Headers[0].KeyID != "" {
		if ks := set.Key(tok.Headers[0].KeyID); len(ks) > 0 {
			key = ks[0]
		}
	}
	var c jwt.Claims
	if err := tok.Claims(key.Key, &c); err != nil {
		return fmt.Errorf("client_assertion signature invalid")
	}
	if err := c.ValidateWithLeeway(jwt.Expected{Issuer: p.Client.ID, Subject: p.Client.ID,
		AnyAudience: jwt.Audience{p.Issuer + "/token", p.Issuer}, Time: p.Now()}, 30*time.Second); err != nil {
		return fmt.Errorf("client_assertion claims: %v", err)
	}
	if f.Get("client_id") != "" && f.Get("client_id") != p.Client.ID {
		return fmt.Errorf("client_id does not match the assertion")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if c.ID == "" || !p.jtis[c.ID].IsZero() {
		return fmt.Errorf("client_assertion jti missing or replayed")
	}
	p.jtis[c.ID] = p.Now()
	return nil
}

func (p *IdP) idToken(g grant) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: p.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", p.kid))
	if err != nil {
		return "", err
	}
	now := p.Now()
	sub := sha256.Sum256([]byte("doctorid|" + g.holder.CollegiateNumber))
	claims := map[string]any{
		"iss": p.Issuer, "sub": hex.EncodeToString(sub[:16]), "aud": g.Client.ID,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "auth_time": g.authAt.Unix(),
		"acr": "http://eidas.europa.eu/LoA/high", "amr": []string{"wallet"}, "credential_type": "doctorid",
		"given_name": g.holder.GivenName, "family_name": g.holder.FamilyName,
		"personal_administrative_number": g.holder.CollegiateNumber,
	}
	if g.Nonce != "" {
		claims["nonce"] = g.Nonce
	}
	for k, v := range g.holder.Data {
		if _, taken := claims[k]; !taken && k != "givenName" && k != "familyName" {
			claims[k] = v
		}
	}
	return jwt.Signed(signer).Claims(claims).Serialize()
}

func tokenError(w http.ResponseWriter, code string) {
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": code})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func randomID() string {
	var b [24]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

var loginPage = template.Must(template.New("login").Parse(`<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Inicio de sesión · DoctorID (simulado)</title>
<style>
body{margin:0;font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;background:#eef2f7;color:#1c2a3a}
.bar{background:#3b2a6b;color:#fff;padding:12px 20px;font-weight:600}.bar small{opacity:.75;font-weight:400;margin-left:8px}
main{max-width:560px;margin:32px auto;padding:0 16px}.card{background:#fff;border-radius:14px;padding:24px;box-shadow:0 6px 24px rgb(0 0 0/.08)}
h1{font-size:1.4rem;margin:0 0 6px}p.muted{color:#5b6779;margin:0 0 18px}
label.opt{display:flex;gap:12px;align-items:flex-start;border:1.5px solid #d6dde8;border-radius:12px;padding:12px 14px;margin-bottom:10px;cursor:pointer}
label.opt:has(input:checked){border-color:#5b3cc4;background:#f4f0ff}label.opt small{display:block;color:#5b6779}
.wallet{display:inline-block;background:#5b3cc4;color:#fff;border-radius:6px;font-size:.75rem;padding:1px 8px;margin-bottom:12px}
button{font:600 1rem system-ui;border-radius:10px;padding:11px 18px;cursor:pointer;border:0}
.primary{background:#5b3cc4;color:#fff}.ghost{background:none;color:#5b6779}.warn{font-size:.85rem;color:#8a4b06;background:#fdf0d9;padding:8px 12px;border-radius:8px;margin-top:16px}
</style></head><body>
<div class="bar">Inicio de sesión<small>Proveedor de identidad DoctorID · SIMULADO</small></div>
<main><div class="card">
<span class="wallet">Mi DoctorID · cartera</span>
<h1>Entrar con tu DoctorID</h1>
<p class="muted">La aplicación <strong>{{.Client}}</strong> te pide que te identifiques. En la realidad presentarías tu DoctorID desde la cartera; aquí eliges cuál.</p>
<form method="post" action="authorize">
<input type="hidden" name="req" value="{{.Req}}">
{{range $i, $h := .Holders}}
<label class="opt"><input type="radio" name="doctorid" value="{{$h.CollegiateNumber}}" {{if eq $i 0}}checked{{end}}>
<span><strong>{{$h.GivenName}} {{$h.FamilyName}}</strong><small>Colegiado {{$h.CollegiateNumber}}{{with $h.Note}} · {{.}}{{end}}</small></span></label>
{{end}}
<p><button class="primary" type="submit">Presentar DoctorID</button></p>
</form>
<form method="post" action="authorize"><input type="hidden" name="req" value="{{.Req}}"><button class="ghost" type="submit">Cancelar y volver</button></form>
<p class="warn">Simulador: solo aparecen los DoctorID emitidos en el simulador, más una médica externa para probar el rechazo.</p>
</div></main></body></html>`))
