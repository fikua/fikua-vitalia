package config

import (
	"strings"
	"testing"
	"time"

	"github.com/fikua/fikua-vitalia/internal/cgcom"
)

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestLoadDefaults(t *testing.T) {
	c, err := Load(envOf(map[string]string{
		"VITALIA_ADAPTER_BASE_URL": "https://adapter.example.test/base/",
		"VITALIA_WEBHOOK_SECRET":   strings.Repeat("s", 32),
		"VITALIA_UI_USER":          "u",
		"VITALIA_UI_PASSWORD":      "p",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.SignatureTolerance != 5*time.Minute || !c.RefreshOnWebhook || !c.CookieSecure || c.AdapterBaseURL.String() != "https://adapter.example.test/base" {
		t.Fatalf("unexpected config %+v", c)
	}
}

func TestLoadFailsFast(t *testing.T) {
	_, err := Load(envOf(map[string]string{
		"VITALIA_ADAPTER_BASE_URL":    "ftp://x",
		"VITALIA_WEBHOOK_SECRET":      "short",
		"VITALIA_SIGNATURE_TOLERANCE": "soon",
	}))
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"VITALIA_UI_USER", "VITALIA_STAFF_OIDC_ISSUER", "VITALIA_ADAPTER_BASE_URL", "VITALIA_WEBHOOK_SECRET", "VITALIA_SIGNATURE_TOLERANCE"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %s: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "short") {
		t.Error("the error must not echo the secret")
	}
}

func TestLoadWithTheClinicIdentityProvider(t *testing.T) {
	base := map[string]string{
		"VITALIA_ADAPTER_BASE_URL":   "https://adapter.example.test",
		"VITALIA_WEBHOOK_SECRET":     strings.Repeat("s", 32),
		"VITALIA_OIDC_ISSUER":        "https://auth.example.test/application/o/vitalia/",
		"VITALIA_OIDC_CLIENT_SECRET": "x",
		"VITALIA_STAFF_OIDC_ISSUER":  "https://auth.example.test/application/o/vitalia/",
	}
	if _, err := Load(envOf(base)); err == nil || !strings.Contains(err.Error(), "VITALIA_STAFF_OIDC_CLIENT_SECRET") {
		t.Fatalf("staff sign-in without secret: %v", err)
	}
	base["VITALIA_STAFF_OIDC_CLIENT_SECRET"] = "y"
	c, err := Load(envOf(base))
	if err != nil {
		t.Fatal(err)
	}
	if c.OIDCSigningKey != nil || c.OIDCSecret != "x" || c.StaffGroup != "Vitalia RRHH" || c.UIUser != "" {
		t.Fatalf("unexpected config %+v", c)
	}
	base["VITALIA_UI_USER"] = "only-user"
	if _, err := Load(envOf(base)); err == nil || !strings.Contains(err.Error(), "go together") {
		t.Fatalf("user without password: %v", err)
	}
}

func TestLoadCGCOMPlatformCredential(t *testing.T) {
	key, _ := cgcom.GenerateKey()
	enc, _ := cgcom.EncodePrivateKey(key)
	base := map[string]string{
		"VITALIA_ADAPTER_BASE_URL": "https://cgcom.dev.example.test/cgcom-adapter",
		"VITALIA_WEBHOOK_SECRET":   strings.Repeat("s", 32),
		"VITALIA_UI_USER":          "u",
		"VITALIA_UI_PASSWORD":      "p",
		"VITALIA_CGCOM_TOKEN_URL":  "https://cgcom.dev.example.test/token",
	}
	_, err := Load(envOf(base))
	if err == nil || !strings.Contains(err.Error(), "VITALIA_CGCOM_CLIENT_ID") || !strings.Contains(err.Error(), "VITALIA_CGCOM_SIGNING_KEY") {
		t.Fatalf("token URL without credential: %v", err)
	}
	base["VITALIA_CGCOM_CLIENT_ID"] = "vitalia"
	base["VITALIA_CGCOM_SIGNING_KEY"] = "bad"
	if _, err := Load(envOf(base)); err == nil || strings.Contains(err.Error(), "bad") {
		t.Fatalf("bad key: %v (and the error must not echo it)", err)
	}
	base["VITALIA_CGCOM_SIGNING_KEY"] = enc
	c, err := Load(envOf(base))
	if err != nil || c.CGCOMSigningKey == nil || !c.CGCOMSigningKey.Equal(key) || c.CGCOMClientID != "vitalia" {
		t.Fatalf("config = %+v, %v", c, err)
	}
}
