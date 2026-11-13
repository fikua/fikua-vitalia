// Package config reads the service configuration once, at startup, from
// environment variables. A missing or invalid mandatory value stops the
// process before it serves anything.
package config

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/fikua/fikua-vitalia/internal/cgcom"
	"github.com/fikua/fikua-vitalia/internal/doctorlogin"
)

// Config is the parsed configuration. It holds secrets: never log it whole.
type Config struct {
	ListenAddr string
	DBPath     string

	// Adapter API (server-to-server).
	AdapterBaseURL *url.URL
	AdapterToken   string // static bearer token (phase 1); empty sends no Authorization header
	AdapterTimeout time.Duration

	// CGCOM platform credential: when CGCOMTokenURL is set, the API token
	// is obtained by private_key_jwt instead of AdapterToken.
	CGCOMTokenURL      string
	CGCOMSigningKey    *ecdsa.PrivateKey
	CGCOMCredential    string // the platform credential (LEARCredentialMachine)
	CGCOMClientID      string // the key's did:key when empty
	CGCOMTokenAudience string // assertion audience; the token URL when empty
	CGCOMTenant        string // X-Tenant of the token request
	CGCOMTokenScope    string

	// Webhook receiver.
	WebhookSecret      []byte
	SignatureTolerance time.Duration
	RefreshOnWebhook   bool

	// DoctorID login of the physicians (OIDC relying party). Disabled when
	// OIDCIssuer is empty.
	PublicURL      *url.URL
	OIDCIssuer     string
	OIDCClientID   string
	OIDCScopes     []string
	OIDCACR        string
	OIDCSigningKey *ecdsa.PrivateKey // private_key_jwt (the DoctorID IdP directly); or
	OIDCSecret     string            // client secret (the clinic's IdP, which federates DoctorID)

	// The clinic's directory (Authentik API): physicians HR registers are
	// provisioned there. Disabled when DirectoryURL is nil.
	DirectoryURL   *url.URL
	DirectoryToken string
	DirectoryGroup string

	// Sign-in of the management staff with the clinic's identity provider
	// (Authentik). Disabled when StaffOIDCIssuer is empty.
	StaffOIDCIssuer   string
	StaffOIDCClientID string
	StaffOIDCSecret   string
	StaffGroup        string // group the ID Token must list in "groups"

	// Operator UI: a local test account, optional when staff sign-in is on.
	UIUser string
	// UIPasswordForm shows the test account's form on the login page. When
	// false the account still works, but the page only offers Authentik.
	UIPasswordForm bool
	UIPassword     string
	CookieSecure   bool
}

const minSecretLen = 32

// Load parses the configuration from getenv (os.Getenv in production).
func Load(getenv func(string) string) (Config, error) {
	var errs []error
	get := func(key, def string) string {
		if v := strings.TrimSpace(getenv(key)); v != "" {
			return v
		}
		return def
	}
	required := func(key string) string {
		v := strings.TrimSpace(getenv(key))
		if v == "" {
			errs = append(errs, fmt.Errorf("%s is required", key))
		}
		return v
	}
	duration := func(key, def string) time.Duration {
		d, err := time.ParseDuration(get(key, def))
		if err != nil || d <= 0 {
			errs = append(errs, fmt.Errorf("%s must be a positive duration such as 5m", key))
		}
		return d
	}
	boolean := func(key, def string) bool {
		b, err := strconv.ParseBool(get(key, def))
		if err != nil {
			errs = append(errs, fmt.Errorf("%s must be true or false", key))
		}
		return b
	}

	c := Config{
		ListenAddr:         get("VITALIA_LISTEN_ADDR", ":8080"),
		DBPath:             get("VITALIA_DB_PATH", "vitalia.db"),
		AdapterToken:       strings.TrimSpace(getenv("VITALIA_ADAPTER_TOKEN")),
		AdapterTimeout:     duration("VITALIA_ADAPTER_TIMEOUT", "15s"),
		SignatureTolerance: duration("VITALIA_SIGNATURE_TOLERANCE", "5m"),
		RefreshOnWebhook:   boolean("VITALIA_REFRESH_ON_WEBHOOK", "true"),
		UIUser:             strings.TrimSpace(getenv("VITALIA_UI_USER")),
		UIPassword:         strings.TrimSpace(getenv("VITALIA_UI_PASSWORD")),
		CookieSecure:       boolean("VITALIA_COOKIE_SECURE", "true"),
		UIPasswordForm:     boolean("VITALIA_UI_PASSWORD_FORM", "true"),
	}

	if raw := required("VITALIA_ADAPTER_BASE_URL"); raw != "" {
		u, err := url.Parse(strings.TrimRight(raw, "/"))
		switch {
		case err != nil || u.Host == "":
			errs = append(errs, errors.New("VITALIA_ADAPTER_BASE_URL must be an absolute URL"))
		case u.Scheme != "https" && u.Scheme != "http":
			errs = append(errs, errors.New("VITALIA_ADAPTER_BASE_URL must use http or https"))
		default:
			c.AdapterBaseURL = u
		}
	}

	if raw := get("VITALIA_PUBLIC_URL", "http://localhost:8080"); raw != "" {
		u, err := url.Parse(strings.TrimRight(raw, "/"))
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			errs = append(errs, errors.New("VITALIA_PUBLIC_URL must be an absolute http(s) URL"))
		} else {
			c.PublicURL = u
		}
	}
	if c.OIDCIssuer = strings.TrimSpace(getenv("VITALIA_OIDC_ISSUER")); c.OIDCIssuer != "" {
		c.OIDCClientID = get("VITALIA_OIDC_CLIENT_ID", "vitalia")
		c.OIDCScopes = strings.Fields(get("VITALIA_OIDC_SCOPES", "openid profile doctorid"))
		c.OIDCACR = strings.TrimSpace(getenv("VITALIA_OIDC_ACR"))
		c.OIDCSecret = strings.TrimSpace(getenv("VITALIA_OIDC_CLIENT_SECRET"))
		if c.OIDCSecret != "" {
			// client secret authentication: no signing key needed
		} else if raw := required("VITALIA_OIDC_SIGNING_KEY"); raw != "" {
			key, err := doctorlogin.ParseSigningKey(raw)
			if err != nil {
				errs = append(errs, fmt.Errorf("VITALIA_OIDC_SIGNING_KEY: %v", err))
			}
			c.OIDCSigningKey = key
		}
	}

	if raw := strings.TrimSpace(getenv("VITALIA_CGCOM_TOKEN_URL")); raw != "" {
		if u, err := url.Parse(raw); err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			errs = append(errs, errors.New("VITALIA_CGCOM_TOKEN_URL must be an absolute http(s) URL"))
		}
		c.CGCOMTokenURL = raw
		c.CGCOMCredential = required("VITALIA_CGCOM_CREDENTIAL")
		c.CGCOMClientID = strings.TrimSpace(getenv("VITALIA_CGCOM_CLIENT_ID"))
		c.CGCOMTokenAudience = strings.TrimSpace(getenv("VITALIA_CGCOM_TOKEN_AUDIENCE"))
		c.CGCOMTenant = get("VITALIA_CGCOM_TENANT", "cgcom")
		c.CGCOMTokenScope = strings.TrimSpace(getenv("VITALIA_CGCOM_TOKEN_SCOPE"))
		if raw := required("VITALIA_CGCOM_SIGNING_KEY"); raw != "" {
			key, err := cgcom.ParsePrivateKey(raw)
			if err != nil {
				errs = append(errs, fmt.Errorf("VITALIA_CGCOM_SIGNING_KEY: %v", err))
			}
			c.CGCOMSigningKey = key
		}
	}

	if raw := strings.TrimSpace(getenv("VITALIA_DIRECTORY_URL")); raw != "" {
		u, err := url.Parse(strings.TrimRight(raw, "/"))
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			errs = append(errs, errors.New("VITALIA_DIRECTORY_URL must be an absolute http(s) URL"))
		}
		c.DirectoryURL = u
		c.DirectoryToken = required("VITALIA_DIRECTORY_TOKEN")
		c.DirectoryGroup = get("VITALIA_DIRECTORY_GROUP", "Vitalia Médicos")
	}

	if c.StaffOIDCIssuer = strings.TrimSpace(getenv("VITALIA_STAFF_OIDC_ISSUER")); c.StaffOIDCIssuer != "" {
		c.StaffOIDCClientID = get("VITALIA_STAFF_OIDC_CLIENT_ID", "vitalia")
		c.StaffOIDCSecret = required("VITALIA_STAFF_OIDC_CLIENT_SECRET")
		c.StaffGroup = get("VITALIA_STAFF_GROUP", "Vitalia RRHH")
	}
	switch {
	case (c.UIUser == "") != (c.UIPassword == ""):
		errs = append(errs, errors.New("VITALIA_UI_USER and VITALIA_UI_PASSWORD go together"))
	case c.UIUser == "" && c.StaffOIDCIssuer == "":
		errs = append(errs, errors.New("the management area needs VITALIA_UI_USER and VITALIA_UI_PASSWORD, or VITALIA_STAFF_OIDC_ISSUER"))
	}

	if secret := required("VITALIA_WEBHOOK_SECRET"); secret != "" {
		if len(secret) < minSecretLen {
			errs = append(errs, fmt.Errorf("VITALIA_WEBHOOK_SECRET must be at least %d characters", minSecretLen))
		}
		c.WebhookSecret = []byte(secret)
	}

	if len(errs) > 0 {
		return Config{}, errors.Join(errs...)
	}
	return c, nil
}
