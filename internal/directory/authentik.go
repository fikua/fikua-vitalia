// Package directory keeps the clinic's identity provider (Authentik) in
// step with the physicians HR registers: a physician must exist there, with
// their registration number as username, to sign in with DoctorID through
// it (the DoctorID source links by that username).
//
// It talks to Authentik's REST API with the token of a service account whose
// role only lets it view and add users and add them to groups.
package directory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// Physician is what the directory needs to know about a physician.
type Physician struct {
	CollegiateNumber     string // the username
	AdministrativeNumber string
	FullName             string
	Email                string
	Specialty            string
}

// Authentik provisions physicians in Authentik.
type Authentik struct {
	BaseURL *url.URL // e.g. https://vitalia-auth.fikua.com
	Token   string   // API token of the service account
	Group   string   // group the physicians belong to
	Path    string   // user path; "users/vitalia/medicos" when empty
	HTTP    *http.Client

	mu      sync.Mutex
	groupPK string
}

// APIError is an unexpected answer of the Authentik API.
type APIError struct {
	Method, Path string
	Status       int
	Body         string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("authentik %s %s: HTTP %d %s", e.Method, e.Path, e.Status, e.Body)
}

type user struct {
	PK         int            `json:"pk,omitempty"`
	Username   string         `json:"username"`
	Name       string         `json:"name"`
	Email      string         `json:"email,omitempty"`
	Path       string         `json:"path,omitempty"`
	Type       string         `json:"type,omitempty"`
	IsActive   bool           `json:"is_active"`
	Groups     []string       `json:"groups"`
	Attributes map[string]any `json:"attributes"`
}

// EnsurePhysician creates the physician's user, or brings it up to date:
// name, e-mail, attributes the clinic owns, active, and in the group. Other
// attributes and groups the user has are kept.
func (a *Authentik) EnsurePhysician(ctx context.Context, p Physician) error {
	if p.CollegiateNumber == "" {
		return errors.New("directory: a physician needs a registration number")
	}
	group, err := a.group(ctx)
	if err != nil {
		return err
	}
	var found struct {
		Results []user `json:"results"`
	}
	if err := a.call(ctx, http.MethodGet, "/api/v3/core/users/?"+url.Values{"username": {p.CollegiateNumber}}.Encode(), nil, &found); err != nil {
		return err
	}
	u := user{Username: p.CollegiateNumber, Type: "internal", Path: a.path(), Attributes: map[string]any{}}
	for _, r := range found.Results {
		if r.Username == p.CollegiateNumber {
			u = r
		}
	}
	if u.Attributes == nil {
		u.Attributes = map[string]any{}
	}
	u.Name, u.IsActive = strings.TrimSpace(p.FullName), true
	if p.Email != "" {
		u.Email = p.Email
	}
	u.Attributes["collegiate_number"] = p.CollegiateNumber
	u.Attributes["administrative_number"] = p.AdministrativeNumber
	if p.Specialty != "" {
		u.Attributes["specialty"] = p.Specialty
	}
	u.Attributes["provisioned_by"] = "vitalia"
	if !slices.Contains(u.Groups, group) {
		u.Groups = append(u.Groups, group)
	}
	if u.PK == 0 {
		return a.call(ctx, http.MethodPost, "/api/v3/core/users/", u, nil)
	}
	return a.call(ctx, http.MethodPatch, fmt.Sprintf("/api/v3/core/users/%d/", u.PK), map[string]any{
		"name": u.Name, "email": u.Email, "is_active": true, "groups": u.Groups, "attributes": u.Attributes,
	}, nil)
}

func (a *Authentik) path() string {
	if a.Path != "" {
		return a.Path
	}
	return "users/vitalia/medicos"
}

// group returns the physicians' group id, looked up once.
func (a *Authentik) group(ctx context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.groupPK != "" {
		return a.groupPK, nil
	}
	var found struct {
		Results []struct {
			PK   string `json:"pk"`
			Name string `json:"name"`
		} `json:"results"`
	}
	if err := a.call(ctx, http.MethodGet, "/api/v3/core/groups/?"+url.Values{"name": {a.Group}}.Encode(), nil, &found); err != nil {
		return "", err
	}
	for _, g := range found.Results {
		if g.Name == a.Group {
			a.groupPK = g.PK
			return g.PK, nil
		}
	}
	return "", fmt.Errorf("directory: group %q not found in Authentik", a.Group)
}

func (a *Authentik) call(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	u := strings.TrimRight(a.BaseURL.String(), "/") + path
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.Token)
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := a.HTTP
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("authentik %s %s: %w", method, strings.SplitN(path, "?", 2)[0], err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		cut := string(raw)
		if len(cut) > 300 {
			cut = cut[:300] + "…"
		}
		return &APIError{Method: method, Path: strings.SplitN(path, "?", 2)[0], Status: resp.StatusCode, Body: cut}
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("authentik %s %s: %w", method, path, err)
		}
	}
	return nil
}
