// Command cgcomkey manages the clinic's CGCOM platform key (ES256).
//
//	cgcomkey          generates a key pair and prints the PRIVATE key
//	                  (base64 PKCS#8 DER, for VITALIA_CGCOM_SIGNING_KEY)
//	cgcomkey -jwk     reads that private key on stdin and prints the PUBLIC
//	                  key as the JWK CGCOM registers (kty, crv, x, y only)
//	cgcomkey -did     reads the private key on stdin and prints its did:key
//	                  (the client_id of the token request)
//	cgcomkey -token   asks the token endpoint for an access token with the
//	                  VITALIA_CGCOM_* environment, and prints the outcome and
//	                  the token's claims (never the token itself)
//
// Generate the key where it will live, so the private half is never copied
// around, and send CGCOM only the -jwk output, e.g. on the host:
//
//	KEY=$(cgcomkey) && echo "VITALIA_CGCOM_SIGNING_KEY=$KEY" >> .env && echo "$KEY" | cgcomkey -jwk
package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/fikua/fikua-vitalia/internal/cgcom"
)

func main() {
	jwk := flag.Bool("jwk", false, "read the private key on stdin and print the public JWK")
	did := flag.Bool("did", false, "read the private key on stdin and print its did:key")
	token := flag.Bool("token", false, "request an access token with the VITALIA_CGCOM_* environment")
	flag.Parse()
	var err error
	switch {
	case *token:
		err = requestToken()
	case *did:
		err = printDID()
	default:
		err = run(*jwk)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "cgcomkey:", err)
		os.Exit(1)
	}
}

func printDID() error {
	key, err := readKey()
	if err != nil {
		return err
	}
	did, err := cgcom.DIDKey(&key.PublicKey)
	if err != nil {
		return err
	}
	fmt.Println(did)
	return nil
}

func readKey() (*ecdsa.PrivateKey, error) {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 64<<10), 64<<10)
	if !in.Scan() {
		return nil, fmt.Errorf("no private key on stdin")
	}
	return cgcom.ParsePrivateKey(in.Text())
}

// requestToken is the first contact with the Verifier: it shows what came
// back without revealing the token.
func requestToken() error {
	key, err := cgcom.ParsePrivateKey(os.Getenv("VITALIA_CGCOM_SIGNING_KEY"))
	if err != nil {
		return err
	}
	src, err := cgcom.NewPrivateKeyJWTSource(cgcom.TokenConfig{
		TokenURL: os.Getenv("VITALIA_CGCOM_TOKEN_URL"), Key: key, Credential: os.Getenv("VITALIA_CGCOM_CREDENTIAL"),
		ClientID: os.Getenv("VITALIA_CGCOM_CLIENT_ID"), Audience: os.Getenv("VITALIA_CGCOM_TOKEN_AUDIENCE"),
		Tenant: envOr("VITALIA_CGCOM_TENANT", "cgcom"), Scope: os.Getenv("VITALIA_CGCOM_TOKEN_SCOPE"),
		HTTP: &http.Client{Timeout: 30 * time.Second},
	})
	if err != nil {
		return err
	}
	did, _ := cgcom.DIDKey(&key.PublicKey)
	fmt.Println("client_id:", did)
	start := time.Now()
	tok, err := src.Token(context.Background())
	if err != nil {
		return fmt.Errorf("after %s: %w", time.Since(start).Round(time.Millisecond), err)
	}
	fmt.Printf("token obtained in %s (%d characters)\n", time.Since(start).Round(time.Millisecond), len(tok))
	if parts := strings.Split(tok, "."); len(parts) == 3 {
		if payload, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
			var claims map[string]any
			if json.Unmarshal(payload, &claims) == nil {
				out, _ := json.MarshalIndent(claims, "", "  ")
				fmt.Println("claims:", string(out))
			}
		}
	}
	return nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func run(jwk bool) error {
	if !jwk {
		key, err := cgcom.GenerateKey()
		if err != nil {
			return err
		}
		enc, err := cgcom.EncodePrivateKey(key)
		if err != nil {
			return err
		}
		fmt.Println(enc)
		return nil
	}
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 64<<10), 64<<10)
	if !in.Scan() {
		return fmt.Errorf("no private key on stdin")
	}
	key, err := cgcom.ParsePrivateKey(in.Text())
	if err != nil {
		return err
	}
	pub, err := cgcom.PublicJWK(&key.PublicKey)
	if err != nil {
		return err
	}
	fmt.Println(string(pub))
	return nil
}
