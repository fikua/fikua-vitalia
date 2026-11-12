package adapterstub_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/fikua/fikua-vitalia/internal/adapter"
	"github.com/fikua/fikua-vitalia/internal/adapterstub"
	"github.com/fikua/fikua-vitalia/internal/webhook"
)

const scimToken = "scim-token"

type scimEnv struct {
	t      *testing.T
	api    *httptest.Server
	mu     sync.Mutex
	events []adapter.Event
	got    chan struct{}
}

func newSCIMEnv(t *testing.T) *scimEnv {
	t.Helper()
	secret := []byte("0123456789abcdef0123456789abcdef")
	e := &scimEnv{t: t, got: make(chan struct{}, 16)}
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if err := webhook.Verify(r.Header.Get(webhook.SignatureHeader), body, secret, time.Now(), 5*time.Minute); err != nil {
			t.Errorf("webhook signature: %v", err)
		}
		var ev adapter.Event
		_ = json.Unmarshal(body, &ev)
		e.mu.Lock()
		e.events = append(e.events, ev)
		e.mu.Unlock()
		e.got <- struct{}{}
	}))
	t.Cleanup(sink.Close)
	stub := &adapterstub.Stub{Token: "rest-token", SCIMToken: scimToken, PortalURL: "https://portal.test/",
		WebhookURL: sink.URL, WebhookSecret: secret}
	e.api = httptest.NewServer(stub.Handler())
	t.Cleanup(e.api.Close)
	return e
}

func (e *scimEnv) do(method, path string, body any) (int, map[string]any) {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.api.URL+"/scim/v2"+path, rd)
	req.Header.Set("Authorization", "Bearer "+scimToken)
	req.Header.Set("Content-Type", "application/scim+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// waitEvent returns the next webhook the stub sent.
func (e *scimEnv) waitEvent() adapter.Event {
	e.t.Helper()
	select {
	case <-e.got:
	case <-time.After(5 * time.Second):
		e.t.Fatal("no webhook received")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.events[len(e.events)-1]
}

func physician(userName, coll string) map[string]any {
	return map[string]any{
		"schemas":  []string{adapterstub.SchemaUser, adapterstub.SchemaExtension},
		"userName": userName, "displayName": "Laia Puig Soler", "active": true,
		"name":                      map[string]any{"givenName": "Laia", "familyName": "Puig Soler"},
		adapterstub.SchemaExtension: map[string]any{"collegiateNumber": coll, "administrativeNumber": "12345678-z"},
	}
}

func ext(res map[string]any) map[string]any {
	m, _ := res[adapterstub.SchemaExtension].(map[string]any)
	return m
}

func TestSCIMProvisioningDrivesEnrolment(t *testing.T) {
	e := newSCIMEnv(t)

	if code, _ := e.do("GET", "/ServiceProviderConfig", nil); code != http.StatusOK {
		t.Fatalf("ServiceProviderConfig: %d", code)
	}

	// Create: enrols the physician and notifies the organisation.
	code, u := e.do("POST", "/Users", physician("lpuig", "282810001"))
	if code != http.StatusCreated {
		t.Fatalf("create: %d %v", code, u)
	}
	id := u["id"].(string)
	if ext(u)["enrollmentState"] != string(adapter.Initiated) || ext(u)["administrativeNumber"] != "12345678Z" {
		t.Fatalf("extension: %v", ext(u))
	}
	ev := e.waitEvent()
	if ev.Event != adapter.EventStateChanged || ev.Enrollment.CollegiateNumber != "282810001" || ev.Enrollment.State != adapter.Initiated {
		t.Fatalf("event on create: %+v", ev)
	}
	first := ev.Enrollment.ID

	// The same userName again: conflict, and the client finds it by filter.
	if code, _ := e.do("POST", "/Users", physician("LPUIG", "282810001")); code != http.StatusConflict {
		t.Fatalf("duplicate: %d", code)
	}
	code, list := e.do("GET", "/Users?filter="+url.QueryEscape(`userName eq "lpuig"`), nil)
	if code != http.StatusOK || list["totalResults"].(float64) != 1 {
		t.Fatalf("filter: %d %v", code, list)
	}

	// Deactivate with PATCH: the open enrolment is cancelled.
	code, u = e.do("PATCH", "/Users/"+id, map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []any{map[string]any{"op": "replace", "value": map[string]any{"active": false}}}})
	if code != http.StatusOK || u["active"] != false || ext(u)["enrollmentState"] != string(adapter.Cancelled) {
		t.Fatalf("deactivate: %d %v", code, u)
	}
	if ev := e.waitEvent(); ev.Enrollment.ID != first || ev.Enrollment.State != adapter.Cancelled {
		t.Fatalf("event on deactivate: %+v", ev)
	}

	// Reactivate with PUT: a new enrolment is opened.
	code, u = e.do("PUT", "/Users/"+id, physician("lpuig", "282810001"))
	if code != http.StatusOK || ext(u)["enrollmentId"] == first || ext(u)["enrollmentState"] != string(adapter.Initiated) {
		t.Fatalf("reactivate: %d %v", code, u)
	}
	second := e.waitEvent().Enrollment.ID

	// Delete: cancels the open enrolment and forgets the user.
	if code, _ := e.do("DELETE", "/Users/"+id, nil); code != http.StatusNoContent {
		t.Fatalf("delete: %d", code)
	}
	if ev := e.waitEvent(); ev.Enrollment.ID != second || ev.Enrollment.State != adapter.Cancelled {
		t.Fatalf("event on delete: %+v", ev)
	}
	if code, _ := e.do("GET", "/Users/"+id, nil); code != http.StatusNotFound {
		t.Fatalf("get after delete: %d", code)
	}
}

func TestSCIMRejectsMissingIdentifiersAndBadToken(t *testing.T) {
	e := newSCIMEnv(t)
	u := physician("jruiz", "12345")
	code, res := e.do("POST", "/Users", u)
	if code != http.StatusBadRequest || res["scimType"] != "invalidValue" {
		t.Fatalf("invalid collegiate number: %d %v", code, res)
	}
	delete(u, adapterstub.SchemaExtension)
	if code, _ := e.do("POST", "/Users", u); code != http.StatusBadRequest {
		t.Fatalf("no extension: %d", code)
	}

	// Already has a DoctorID: straight to PENDING_CONFIRMATION.
	code, res = e.do("POST", "/Users", physician("mgarcia", "282810010"))
	if code != http.StatusCreated || ext(res)["enrollmentState"] != string(adapter.PendingConfirmation) {
		t.Fatalf("existing DoctorID: %d %v", code, res)
	}

	req, _ := http.NewRequest("GET", e.api.URL+"/scim/v2/Users", nil)
	req.Header.Set("Authorization", "Bearer rest-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("REST token on SCIM: %d", resp.StatusCode)
	}
}
