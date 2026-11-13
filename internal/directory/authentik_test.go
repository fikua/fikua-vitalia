package directory_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/fikua/fikua-vitalia/internal/directory"
)

// fakeAuthentik keeps users in memory and checks the token.
type fakeAuthentik struct {
	mu     sync.Mutex
	users  map[int]map[string]any
	next   int
	writes []string
}

func (f *fakeAuthentik) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer dir-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v3/core/groups/":
			res := []any{}
			if r.URL.Query().Get("name") == "Vitalia Médicos" {
				res = append(res, map[string]any{"pk": "g-medicos", "name": "Vitalia Médicos"})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"results": res})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v3/core/users/":
			res := []any{}
			for _, u := range f.users {
				if u["username"] == r.URL.Query().Get("username") {
					res = append(res, u)
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"results": res})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v3/core/users/":
			var u map[string]any
			_ = json.NewDecoder(r.Body).Decode(&u)
			f.next++
			u["pk"] = f.next
			f.users[f.next] = u
			f.writes = append(f.writes, "create")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(u)
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/api/v3/core/users/"):
			pk, _ := strconv.Atoi(strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v3/core/users/"), "/"))
			var patch map[string]any
			_ = json.NewDecoder(r.Body).Decode(&patch)
			for k, v := range patch {
				f.users[pk][k] = v
			}
			f.writes = append(f.writes, "update")
			_ = json.NewEncoder(w).Encode(f.users[pk])
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func TestEnsurePhysicianCreatesThenUpdates(t *testing.T) {
	f := &fakeAuthentik{users: map[int]map[string]any{}}
	srv := httptest.NewServer(f.handler(t))
	t.Cleanup(srv.Close)
	base, _ := url.Parse(srv.URL)
	a := &directory.Authentik{BaseURL: base, Token: "dir-token", Group: "Vitalia Médicos"}
	ctx := context.Background()

	p := directory.Physician{CollegiateNumber: "282812345", AdministrativeNumber: "12345678Z", FullName: "María García López", Specialty: "Cardiología"}
	if err := a.EnsurePhysician(ctx, p); err != nil {
		t.Fatal(err)
	}
	u := f.users[1]
	attrs := u["attributes"].(map[string]any)
	if u["username"] != "282812345" || u["name"] != "María García López" || u["path"] != "users/vitalia/medicos" ||
		u["type"] != "internal" || attrs["collegiate_number"] != "282812345" || attrs["administrative_number"] != "12345678Z" ||
		len(u["groups"].([]any)) != 1 || u["groups"].([]any)[0] != "g-medicos" {
		t.Fatalf("created user = %v", u)
	}

	// Someone added an attribute and a group in Authentik; HR fixes the name.
	attrs["note"] = "kept"
	u["groups"] = []any{"g-medicos", "g-other"}
	p.FullName = "María García-López"
	if err := a.EnsurePhysician(ctx, p); err != nil {
		t.Fatal(err)
	}
	u = f.users[1]
	attrs = u["attributes"].(map[string]any)
	if len(f.users) != 1 || u["name"] != "María García-López" || attrs["note"] != "kept" || len(u["groups"].([]any)) != 2 {
		t.Fatalf("updated user = %v", u)
	}
	if strings.Join(f.writes, ",") != "create,update" {
		t.Fatalf("writes = %v", f.writes)
	}

	// A wrong token surfaces as an API error.
	bad := &directory.Authentik{BaseURL: base, Token: "nope", Group: "Vitalia Médicos"}
	var apiErr *directory.APIError
	if err := bad.EnsurePhysician(ctx, p); !errors.As(err, &apiErr) || apiErr.Status != http.StatusForbidden {
		t.Fatalf("bad token: %v", err)
	}
	// A missing group is reported, not created.
	missing := &directory.Authentik{BaseURL: base, Token: "dir-token", Group: "Nope"}
	if err := missing.EnsurePhysician(ctx, p); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing group: %v", err)
	}
}
