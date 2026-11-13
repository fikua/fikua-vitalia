package cgcom

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// TokenSource gives the bearer token for each call. Phase 1 has a static
// token; phase 2 adds the M2M one obtained from the Verifier.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// StaticTokenSource returns a fixed token. Empty means "send no token".
type StaticTokenSource string

func (s StaticTokenSource) Token(context.Context) (string, error) { return string(s), nil }

// Call is one request to the adapter and its outcome, for the call log.
type Call struct {
	At           time.Time
	Operation    string
	Method       string
	Path         string
	RequestBody  string
	Status       int
	ProblemType  string
	ResponseBody string
	RetryAfter   string
	Duration     time.Duration
	Error        string
	EnrollmentID string
}

// CallRecorder stores calls. Recording failures never fail the call.
type CallRecorder interface {
	RecordCall(ctx context.Context, c Call) error
}

// Result of a successful call that returns an enrolment.
type Result struct {
	Enrollment Enrollment
	Raw        []byte
	Status     int
}

// ProblemError is a non-2xx answer from the adapter.
type ProblemError struct {
	Status     int
	Problem    Problem // zero when the body was not problem+json
	RetryAfter time.Duration
	HasRetry   bool
}

func (e *ProblemError) Error() string {
	if e.Problem.Type != "" {
		return fmt.Sprintf("adapter answered %d %s: %s", e.Status, e.Problem.Type, e.Problem.Detail)
	}
	return fmt.Sprintf("adapter answered %d", e.Status)
}

// Client calls the enrolment API of the adapter.
type Client struct {
	base     *url.URL
	http     *http.Client
	tokens   TokenSource
	recorder CallRecorder
	now      func() time.Time
}

const maxResponseBody = 1 << 20

// NewClient builds a client. httpClient carries the timeout.
func NewClient(base *url.URL, httpClient *http.Client, tokens TokenSource, recorder CallRecorder) *Client {
	return &Client{base: base, http: httpClient, tokens: tokens, recorder: recorder, now: time.Now}
}

// CreateEnrollment enrols a physician. Status 201 is a new enrolment, 200 the
// platform's existing open one for the same pair.
func (c *Client) CreateEnrollment(ctx context.Context, administrativeNumber, collegiateNumber string) (Result, error) {
	body, _ := json.Marshal(map[string]string{
		"administrative_number": administrativeNumber,
		"collegiate_number":     collegiateNumber,
	})
	return c.do(ctx, "createEnrollment", http.MethodPost, "/api/v1/enrollments", "", body, http.StatusCreated, http.StatusOK)
}

// GetEnrollment reads an enrolment: the source of truth.
func (c *Client) GetEnrollment(ctx context.Context, id string) (Result, error) {
	if !ValidID(id) {
		return Result{}, fmt.Errorf("invalid enrollment id")
	}
	return c.do(ctx, "getEnrollment", http.MethodGet, "/api/v1/enrollments/"+id, id, nil, http.StatusOK)
}

// Decision on the physician's DoctorID data.
type Decision string

const (
	Confirm Decision = "confirm"
	Reject  Decision = "reject"
)

// Decide confirms or rejects. The attestation is left out (not defined yet).
func (c *Client) Decide(ctx context.Context, id string, d Decision) (Result, error) {
	if !ValidID(id) {
		return Result{}, fmt.Errorf("invalid enrollment id")
	}
	if d != Confirm && d != Reject {
		return Result{}, fmt.Errorf("invalid decision %q", d)
	}
	body, _ := json.Marshal(map[string]string{"decision": string(d)})
	return c.do(ctx, "confirmEnrollment", http.MethodPost, "/api/v1/enrollments/"+id+"/confirmation", id, body, http.StatusOK)
}

// Cancel cancels an enrolment.
func (c *Client) Cancel(ctx context.Context, id string) (Result, error) {
	if !ValidID(id) {
		return Result{}, fmt.Errorf("invalid enrollment id")
	}
	return c.do(ctx, "cancelEnrollment", http.MethodPost, "/api/v1/enrollments/"+id+"/cancellation", id, nil, http.StatusOK)
}

func (c *Client) do(ctx context.Context, op, method, path, enrollmentID string, body []byte, okStatus ...int) (Result, error) {
	call := Call{At: c.now().UTC(), Operation: op, Method: method, Path: path, RequestBody: string(body), EnrollmentID: enrollmentID}
	start := time.Now()
	res, err := c.send(ctx, method, path, body, &call, okStatus)
	// A refused token (expired early, revoked, key rotated): drop it and try
	// once more with a new one.
	var pe *ProblemError
	if inv, ok := c.tokens.(interface{ Invalidate() }); ok && errors.As(err, &pe) && pe.Status == http.StatusUnauthorized {
		inv.Invalidate()
		res, err = c.send(ctx, method, path, body, &call, okStatus)
	}
	call.Duration = time.Since(start)
	if err != nil {
		call.Error = err.Error()
	}
	if call.EnrollmentID == "" {
		call.EnrollmentID = res.Enrollment.ID // the create call learns the id from its response
	}
	if c.recorder != nil {
		// Recording is evidence, not part of the operation: a failure here is
		// not surfaced to the caller.
		_ = c.recorder.RecordCall(context.WithoutCancel(ctx), call)
	}
	return res, err
}

func (c *Client) send(ctx context.Context, method, path string, body []byte, call *Call, okStatus []int) (Result, error) {
	u := c.base.JoinPath(path)
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), reader)
	if err != nil {
		return Result{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json, application/problem+json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("get token: %w", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("call adapter: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return Result{}, fmt.Errorf("read response: %w", err)
	}
	call.Status = resp.StatusCode
	call.ResponseBody = string(raw)
	call.RetryAfter = resp.Header.Get("Retry-After")

	for _, s := range okStatus {
		if resp.StatusCode == s {
			e, err := DecodeEnrollment(raw)
			if err != nil {
				return Result{}, fmt.Errorf("decode enrollment: %w", err)
			}
			if !ValidID(e.ID) || e.State == "" {
				return Result{}, errors.New("adapter returned an enrollment without id or state")
			}
			return Result{Enrollment: e, Raw: raw, Status: resp.StatusCode}, nil
		}
	}

	pe := &ProblemError{Status: resp.StatusCode}
	if mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mt == "application/problem+json" || mt == "application/json" {
		_ = json.Unmarshal(raw, &pe.Problem)
	}
	call.ProblemType = pe.Problem.Type
	if ra := resp.Header.Get("Retry-After"); ra != "" {
		pe.RetryAfter, pe.HasRetry = parseRetryAfter(ra, c.now())
	}
	return Result{}, pe
}

// parseRetryAfter accepts seconds (the contract) or an HTTP date.
func parseRetryAfter(v string, now time.Time) (time.Duration, bool) {
	if n, err := strconv.Atoi(v); err == nil && n >= 0 {
		return time.Duration(n) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := t.Sub(now); d > 0 {
			return d, true
		}
		return 0, true
	}
	return 0, false
}
