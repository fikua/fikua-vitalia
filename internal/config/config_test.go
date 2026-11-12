package config

import (
	"strings"
	"testing"
	"time"
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
	for _, want := range []string{"VITALIA_UI_USER", "VITALIA_UI_PASSWORD", "VITALIA_ADAPTER_BASE_URL", "VITALIA_WEBHOOK_SECRET", "VITALIA_SIGNATURE_TOLERANCE"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %s: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "short") {
		t.Error("the error must not echo the secret")
	}
}
