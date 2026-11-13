package cgcom_test

import (
	"crypto/ecdsa"
	"testing"

	"github.com/go-jose/go-jose/v4"

	"github.com/fikua/fikua-vitalia/internal/cgcom"
)

// Clínica Vitalia's platform key and the did:key CGCOM put in its credential
// (mandatee.id): the derivation must give exactly that value.
func TestDIDKeyMatchesTheCredential(t *testing.T) {
	var jwk jose.JSONWebKey
	if err := jwk.UnmarshalJSON([]byte(`{"kty":"EC","crv":"P-256","x":"P5N-gnsH2OMBoNqb1ivU1Rd97ymRm9rDIBfLQH06Hcw","y":"fnEBrhXeCPRYGL6s-ksPhlEoNuckl35tV--VWl9m1P8"}`)); err != nil {
		t.Fatal(err)
	}
	did, err := cgcom.DIDKey(jwk.Key.(*ecdsa.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if want := "did:key:zDnaemwTYeERGFiFZFgZzB3nPtPwUNF1tHunWiRQ8nkNTUmQo"; did != want {
		t.Fatalf("did:key = %s, want %s", did, want)
	}
}
