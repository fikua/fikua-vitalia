// Command cgcomkey manages the clinic's CGCOM platform key (ES256).
//
//	cgcomkey          generates a key pair and prints the PRIVATE key
//	                  (base64 PKCS#8 DER, for VITALIA_CGCOM_SIGNING_KEY)
//	cgcomkey -jwk     reads that private key on stdin and prints the PUBLIC
//	                  key as the JWK CGCOM registers (kty, crv, x, y only)
//
// Generate the key where it will live, so the private half is never copied
// around, and send CGCOM only the -jwk output, e.g. on the host:
//
//	KEY=$(cgcomkey) && echo "VITALIA_CGCOM_SIGNING_KEY=$KEY" >> .env && echo "$KEY" | cgcomkey -jwk
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"

	"github.com/fikua/fikua-vitalia/internal/cgcom"
)

func main() {
	jwk := flag.Bool("jwk", false, "read the private key on stdin and print the public JWK")
	flag.Parse()
	if err := run(*jwk); err != nil {
		fmt.Fprintln(os.Stderr, "cgcomkey:", err)
		os.Exit(1)
	}
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
