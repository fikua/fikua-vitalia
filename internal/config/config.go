// Package config reads the service configuration once, at startup, from
// environment variables. A missing or invalid mandatory value stops the
// process before it serves anything.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Config is the parsed configuration. It holds secrets: never log it whole.
type Config struct {
	ListenAddr string
	DBPath     string

	// Adapter API (server-to-server).
	AdapterBaseURL *url.URL
	AdapterToken   string // static bearer token (phase 1); empty sends no Authorization header
	AdapterTimeout time.Duration

	// Webhook receiver.
	WebhookSecret      []byte
	SignatureTolerance time.Duration
	RefreshOnWebhook   bool

	// Operator UI.
	UIUser       string
	UIPassword   string
	CookieSecure bool
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
		UIUser:             required("VITALIA_UI_USER"),
		UIPassword:         required("VITALIA_UI_PASSWORD"),
		CookieSecure:       boolean("VITALIA_COOKIE_SECURE", "true"),
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
