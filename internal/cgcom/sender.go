package cgcom

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Send posts body to url signed with secret, as the adapter does. It is used
// by the test CLI and the local adapter stub. It returns the status code and
// the response body.
func Send(ctx context.Context, client *http.Client, url string, secret, body []byte, at time.Time) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, "", fmt.Errorf("build webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(SignatureHeader, Sign(secret, at, body))
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("send webhook: %w", err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, string(out), nil
}
