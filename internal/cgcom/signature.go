package cgcom

// Signature of the enrolment notifications CGCOM sends to the platform.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// SignatureHeader carries "t=<unix seconds>,v1=<hex>".
const SignatureHeader = "X-EUDIStack-Signature"

const maxHeaderLen = 1024

var (
	ErrMissingSignature     = errors.New("missing signature header")
	ErrMalformedSignature   = errors.New("malformed signature header")
	ErrTimestampOutOfWindow = errors.New("signature timestamp outside the tolerance window")
	ErrSignatureMismatch    = errors.New("signature does not match")
)

// Sign returns the header value for body signed with secret at time t.
func Sign(secret []byte, t time.Time, body []byte) string {
	ts := t.Unix()
	return fmt.Sprintf("t=%d,v1=%s", ts, hex.EncodeToString(mac(secret, ts, body)))
}

// Verify checks header against the raw body bytes. It accepts several v1
// values (any one matching is enough, so a secret can be rotated), ignores
// unknown schemes and rejects timestamps more than tolerance away from now,
// in the past or in the future.
func Verify(header string, body, secret []byte, now time.Time, tolerance time.Duration) error {
	header = strings.TrimSpace(header)
	if header == "" {
		return ErrMissingSignature
	}
	if len(header) > maxHeaderLen {
		return ErrMalformedSignature
	}

	var (
		ts    int64
		hasTS bool
		sigs  [][]byte
	)
	for _, part := range strings.Split(header, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return ErrMalformedSignature
		}
		switch key {
		case "t":
			n, err := strconv.ParseInt(value, 10, 64)
			if hasTS || err != nil || n <= 0 {
				return ErrMalformedSignature
			}
			ts, hasTS = n, true
		case "v1":
			sig, err := hex.DecodeString(value)
			if err != nil || len(sig) != sha256.Size {
				return ErrMalformedSignature
			}
			sigs = append(sigs, sig)
		}
	}
	if !hasTS || len(sigs) == 0 {
		return ErrMalformedSignature
	}

	skew := now.Sub(time.Unix(ts, 0))
	if skew < 0 {
		skew = -skew
	}
	if skew > tolerance {
		return ErrTimestampOutOfWindow
	}

	expected := mac(secret, ts, body)
	for _, sig := range sigs {
		if hmac.Equal(sig, expected) {
			return nil
		}
	}
	return ErrSignatureMismatch
}

func mac(secret []byte, ts int64, body []byte) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(strconv.FormatInt(ts, 10)))
	h.Write([]byte("."))
	h.Write(body)
	return h.Sum(nil)
}
