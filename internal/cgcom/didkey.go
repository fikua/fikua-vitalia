package cgcom

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"math/big"
)

// DIDKey is the did:key of a P-256 public key: multicodec p256-pub (0x1200,
// varint 0x80 0x24) followed by the SEC1 compressed point, in base58btc
// ("z"). CGCOM's platform credential names the platform by it
// (mandatee.id), and it is the client_id of the token request.
func DIDKey(k *ecdsa.PublicKey) (string, error) {
	if k.Curve != elliptic.P256() {
		return "", errors.New("did:key: the key must be EC P-256")
	}
	raw, err := k.Bytes() // 0x04 || X || Y
	if err != nil {
		return "", err
	}
	compressed := make([]byte, 0, 35)
	compressed = append(compressed, 0x80, 0x24)
	if raw[64]&1 == 0 { // parity of Y
		compressed = append(compressed, 0x02)
	} else {
		compressed = append(compressed, 0x03)
	}
	compressed = append(compressed, raw[1:33]...)
	return "did:key:z" + base58(compressed), nil
}

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58(b []byte) string {
	n := new(big.Int).SetBytes(b)
	base, mod := big.NewInt(58), new(big.Int)
	var out []byte
	for n.Sign() > 0 {
		n.DivMod(n, base, mod)
		out = append(out, base58Alphabet[mod.Int64()])
	}
	for _, c := range b { // leading zero bytes are "1"
		if c != 0 {
			break
		}
		out = append(out, '1')
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}
