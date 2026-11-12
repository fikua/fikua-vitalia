package webhook

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var (
	secret = []byte("0123456789abcdef0123456789abcdef")
	body   = []byte(`{"event_id":"e","event":"enrollment_state_changed"}`)
	now    = time.Unix(1_800_000_000, 0)
)

func TestVerify(t *testing.T) {
	valid := Sign(secret, now, body)
	_, v1, _ := strings.Cut(valid, ",")

	tests := []struct {
		name   string
		header string
		body   []byte
		secret []byte
		at     time.Time
		want   error
	}{
		{"valid", valid, body, secret, now, nil},
		{"valid within window, past", valid, body, secret, now.Add(4 * time.Minute), nil},
		{"valid within window, future", valid, body, secret, now.Add(-4 * time.Minute), nil},
		{"wrong secret", valid, body, []byte("another-secret-another-secret-xx"), now, ErrSignatureMismatch},
		{"altered body", valid, append([]byte(nil), append(body, ' ')...), secret, now, ErrSignatureMismatch},
		{"missing header", "", body, secret, now, ErrMissingSignature},
		{"blank header", "   ", body, secret, now, ErrMissingSignature},
		{"no timestamp", v1, body, secret, now, ErrMalformedSignature},
		{"no signature", "t=1800000000", body, secret, now, ErrMalformedSignature},
		{"not key=value", "garbage", body, secret, now, ErrMalformedSignature},
		{"bad hex", "t=1800000000,v1=zz", body, secret, now, ErrMalformedSignature},
		{"short signature", "t=1800000000,v1=abcd", body, secret, now, ErrMalformedSignature},
		{"non numeric timestamp", "t=abc," + v1, body, secret, now, ErrMalformedSignature},
		{"two timestamps", "t=1800000000,t=1800000000," + v1, body, secret, now, ErrMalformedSignature},
		{"too long", "t=1800000000," + v1 + strings.Repeat(",x=y", 300), body, secret, now, ErrMalformedSignature},
		{"too old", valid, body, secret, now.Add(6 * time.Minute), ErrTimestampOutOfWindow},
		{"in the future", valid, body, secret, now.Add(-6 * time.Minute), ErrTimestampOutOfWindow},
		{"timestamp swapped keeps signature invalid", strings.Replace(valid, "t=1800000000", "t=1800000001", 1), body, secret, now, ErrSignatureMismatch},
		{"rotation: second v1 matches", "t=1800000000,v1=" + strings.Repeat("00", 32) + "," + v1, body, secret, now, nil},
		{"unknown scheme ignored", valid + ",v0=whatever", body, secret, now, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Verify(tt.header, tt.body, tt.secret, tt.at, 5*time.Minute)
			if !errors.Is(err, tt.want) {
				t.Fatalf("Verify() = %v, want %v", err, tt.want)
			}
		})
	}
}
