package cgcom

// The platform credential: an EC P-256 (ES256) key pair. The clinic keeps
// the private key; CGCOM registers the public one as a JWK.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"

	"github.com/go-jose/go-jose/v4"
)

// GenerateKey creates a new P-256 key pair.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// EncodePrivateKey returns the private key as base64 PKCS#8 DER, the form
// the clinic's configuration reads (VITALIA_CGCOM_SIGNING_KEY).
func EncodePrivateKey(k *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

// PublicJWK is the public key as CGCOM wants it: exactly kty, crv, x and y.
// It never contains d.
func PublicJWK(k *ecdsa.PublicKey) ([]byte, error) {
	if k.Curve != elliptic.P256() {
		return nil, errors.New("the platform key must be EC P-256")
	}
	raw, err := k.Bytes() // uncompressed point: 0x04 || X || Y
	if err != nil {
		return nil, err
	}
	enc := base64.RawURLEncoding.EncodeToString
	return json.Marshal(struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}{"EC", "P-256", enc(raw[1:33]), enc(raw[33:65])})
}

// KeyThumbprint is the RFC 7638 thumbprint of the public key, used as the
// kid of the client assertions.
func KeyThumbprint(k *ecdsa.PublicKey) (string, error) {
	t, err := (&jose.JSONWebKey{Key: k}).Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(t), nil
}

// ParsePrivateKey reads a P-256 private key in base64 PKCS#8 DER (or PEM).
func ParsePrivateKey(s string) (*ecdsa.PrivateKey, error) {
	s = strings.TrimSpace(s)
	var der []byte
	if block, _ := pem.Decode([]byte(s)); block != nil {
		der = block.Bytes
	} else {
		var err error
		if der, err = base64.StdEncoding.DecodeString(s); err != nil {
			return nil, errors.New("signing key: not base64 PKCS#8 DER nor PEM")
		}
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, errors.New("signing key: not a PKCS#8 private key")
	}
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("signing key: must be an EC P-256 key")
	}
	return ec, nil
}
