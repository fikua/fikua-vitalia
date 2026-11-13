package adapterstub

// SCIM 2.0 (RFC 7643, RFC 7644) in front of the enrolment API: an
// organisation's directory (Authentik, Entra ID, Okta...) provisions its
// physicians and the service enrols them. It is a proposal written to learn
// what the real service needs, not its contract:
//
//   - POST /Users enrols the physician; the identifiers travel in the
//     ExtensionSchema extension (collegiateNumber, administrativeNumber).
//   - active=false (PUT or PATCH) and DELETE cancel the open enrolment.
//   - active=true, or new identifiers, open a new enrolment when there is
//     no open one.
//   - Every enrolment opened or cancelled this way is notified with the
//     usual signed webhook, since the organisation never called the REST
//     API and does not know the enrolment id.
//   - The response carries the enrolment id and state in the extension,
//     read only.
//
// Groups are accepted and kept, but mean nothing to the service.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/fikua/fikua-vitalia/internal/cgcom"
)

// SCIM schema URNs.
const (
	SchemaUser      = "urn:ietf:params:scim:schemas:core:2.0:User"
	SchemaGroup     = "urn:ietf:params:scim:schemas:core:2.0:Group"
	SchemaExtension = "urn:eudistack:params:scim:schemas:extension:doctorid:1.0:User"
	schemaList      = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	schemaError     = "urn:ietf:params:scim:api:messages:2.0:Error"
	schemaPatch     = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	scimPrefix      = "/scim/v2"
)

type scimUser struct {
	id         string
	userName   string
	externalID string
	active     bool
	admin      string
	coll       string
	enrollment string // latest enrolment opened for this user
	raw        map[string]any
	created    time.Time
	modified   time.Time
}

// SCIMUser is a provisioned user as the simulator page shows it.
type SCIMUser struct {
	ID, UserName, DisplayName, CollegiateNumber, EnrollmentID string
	Active                                                    bool
	State                                                     cgcom.State
}

func (s *Stub) scimRoutes(mux *http.ServeMux) {
	h := func(f http.HandlerFunc) http.HandlerFunc { return s.scimAuth(f) }
	mux.HandleFunc("GET "+scimPrefix+"/ServiceProviderConfig", h(s.scimConfig))
	mux.HandleFunc("GET "+scimPrefix+"/ResourceTypes", h(s.scimResourceTypes))
	mux.HandleFunc("GET "+scimPrefix+"/Schemas", h(s.scimSchemas))
	mux.HandleFunc("GET "+scimPrefix+"/Users", h(s.scimListUsers))
	mux.HandleFunc("POST "+scimPrefix+"/Users", h(s.scimCreateUser))
	mux.HandleFunc("GET "+scimPrefix+"/Users/{id}", h(s.scimGetUser))
	mux.HandleFunc("PUT "+scimPrefix+"/Users/{id}", h(s.scimReplaceUser))
	mux.HandleFunc("PATCH "+scimPrefix+"/Users/{id}", h(s.scimPatchUser))
	mux.HandleFunc("DELETE "+scimPrefix+"/Users/{id}", h(s.scimDeleteUser))
	mux.HandleFunc("GET "+scimPrefix+"/Groups", h(s.scimListGroups))
	mux.HandleFunc("POST "+scimPrefix+"/Groups", h(s.scimPutGroup))
	mux.HandleFunc("GET "+scimPrefix+"/Groups/{id}", h(s.scimGetGroup))
	mux.HandleFunc("PUT "+scimPrefix+"/Groups/{id}", h(s.scimPutGroup))
	mux.HandleFunc("PATCH "+scimPrefix+"/Groups/{id}", h(s.scimGetGroup)) // members mean nothing here
	mux.HandleFunc("DELETE "+scimPrefix+"/Groups/{id}", h(s.scimDeleteGroup))
}

func (s *Stub) scimAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := s.SCIMToken
		if token == "" {
			token = s.Token
		}
		h := r.Header.Get("Authorization")
		if h == "" || (token != "" && h != "Bearer "+token) {
			scimError(w, http.StatusUnauthorized, "", "Missing or invalid bearer token.")
			return
		}
		next(w, r)
	}
}

func (s *Stub) scimConfig(w http.ResponseWriter, _ *http.Request) {
	scimJSON(w, http.StatusOK, map[string]any{
		"schemas":        []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"patch":          map[string]any{"supported": true},
		"bulk":           map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":         map[string]any{"supported": true, "maxResults": 200},
		"changePassword": map[string]any{"supported": false},
		"sort":           map[string]any{"supported": false},
		"etag":           map[string]any{"supported": false},
		"authenticationSchemes": []map[string]any{{
			"type": "oauthbearertoken", "name": "Bearer token", "description": "Static bearer token (simulator)",
		}},
	})
}

func (s *Stub) scimResourceTypes(w http.ResponseWriter, _ *http.Request) {
	scimJSON(w, http.StatusOK, listResponse([]any{
		map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": "User", "name": "User",
			"endpoint": "/Users", "schema": SchemaUser,
			"schemaExtensions": []map[string]any{{"schema": SchemaExtension, "required": true}}},
		map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": "Group", "name": "Group",
			"endpoint": "/Groups", "schema": SchemaGroup},
	}, 1))
}

func (s *Stub) scimSchemas(w http.ResponseWriter, _ *http.Request) {
	attr := func(name, desc string, required, readOnly bool) map[string]any {
		m := map[string]any{"name": name, "type": "string", "multiValued": false, "description": desc,
			"required": required, "caseExact": true, "mutability": "readWrite", "returned": "default", "uniqueness": "none"}
		if readOnly {
			m["mutability"] = "readOnly"
		}
		return m
	}
	scimJSON(w, http.StatusOK, listResponse([]any{map[string]any{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"}, "id": SchemaExtension,
		"name": "DoctorID enrolment", "description": "Identifiers the enrolment service needs (proposal).",
		"attributes": []any{
			attr("collegiateNumber", "CGCOM registration number, 9 digits.", true, false),
			attr("administrativeNumber", "DNI, NIE or passport number.", true, false),
			attr("enrollmentId", "Latest enrolment opened for this user.", false, true),
			attr("enrollmentState", "State of that enrolment.", false, true),
		},
	}}, 1))
}

// ------------------------------------------------------------------- users

func (s *Stub) scimListUsers(w http.ResponseWriter, r *http.Request) {
	attr, value, err := parseFilter(r.URL.Query().Get("filter"))
	if err != nil {
		scimError(w, http.StatusBadRequest, "invalidFilter", err.Error())
		return
	}
	start, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
	if start < 1 {
		start = 1
	}
	count, err := strconv.Atoi(r.URL.Query().Get("count"))
	if err != nil || count <= 0 || count > 200 {
		count = 200
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var all []any
	for _, id := range s.uord {
		u := s.users[id]
		switch attr {
		case "username":
			if !strings.EqualFold(u.userName, value) {
				continue
			}
		case "externalid":
			if u.externalID != value {
				continue
			}
		}
		all = append(all, s.resourceLocked(u))
	}
	total := len(all)
	page := []any{}
	if start-1 < total {
		page = all[start-1 : min(total, start-1+count)]
	}
	resp := listResponse(page, start)
	resp["totalResults"] = total
	scimJSON(w, http.StatusOK, resp)
}

func (s *Stub) scimGetUser(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[r.PathValue("id")]
	if !ok {
		scimError(w, http.StatusNotFound, "", "No such user.")
		return
	}
	scimJSON(w, http.StatusOK, s.resourceLocked(u))
}

func (s *Stub) scimCreateUser(w http.ResponseWriter, r *http.Request) {
	in, ok := decodeSCIM(w, r)
	if !ok {
		return
	}
	u, msg := userFrom(in)
	if msg != "" {
		scimError(w, http.StatusBadRequest, "invalidValue", msg)
		return
	}
	s.mu.Lock()
	for _, other := range s.users {
		if strings.EqualFold(other.userName, u.userName) {
			s.mu.Unlock()
			scimError(w, http.StatusConflict, "uniqueness", "userName already exists.")
			return
		}
	}
	now := s.now()
	u.id, u.created, u.modified = newUUID(), now, now
	events, err := s.reconcileLocked(u, nil)
	if err != nil {
		s.mu.Unlock()
		w.Header().Set("Retry-After", "30")
		scimError(w, http.StatusServiceUnavailable, "", "The issuer did not answer. Nothing was created.")
		return
	}
	if s.users == nil {
		s.users = map[string]*scimUser{}
	}
	s.users[u.id] = u
	s.uord = append(s.uord, u.id)
	out := s.resourceLocked(u)
	s.mu.Unlock()
	s.notify(events)
	scimJSON(w, http.StatusCreated, out)
}

func (s *Stub) scimReplaceUser(w http.ResponseWriter, r *http.Request) {
	in, ok := decodeSCIM(w, r)
	if !ok {
		return
	}
	next, msg := userFrom(in)
	if msg != "" {
		scimError(w, http.StatusBadRequest, "invalidValue", msg)
		return
	}
	s.update(w, r.PathValue("id"), func(*scimUser) (*scimUser, string) { return next, "" })
}

// scimPatchUser applies the operations to the stored representation and
// then handles the result like a PUT.
func (s *Stub) scimPatchUser(w http.ResponseWriter, r *http.Request) {
	in, ok := decodeSCIM(w, r)
	if !ok {
		return
	}
	ops, _ := in["Operations"].([]any)
	if len(ops) == 0 {
		scimError(w, http.StatusBadRequest, "invalidSyntax", "PatchOp needs Operations.")
		return
	}
	s.update(w, r.PathValue("id"), func(cur *scimUser) (*scimUser, string) {
		doc := deepCopy(cur.raw)
		for _, raw := range ops {
			op, _ := raw.(map[string]any)
			if err := applyPatch(doc, op); err != nil {
				return nil, err.Error()
			}
		}
		return userFrom(doc)
	})
}

// update replaces the user with what change returns and reconciles its
// enrolment.
func (s *Stub) update(w http.ResponseWriter, id string, change func(*scimUser) (*scimUser, string)) {
	s.mu.Lock()
	cur, ok := s.users[id]
	if !ok {
		s.mu.Unlock()
		scimError(w, http.StatusNotFound, "", "No such user.")
		return
	}
	next, msg := change(cur)
	if msg != "" {
		s.mu.Unlock()
		scimError(w, http.StatusBadRequest, "invalidValue", msg)
		return
	}
	for _, other := range s.users {
		if other.id != id && strings.EqualFold(other.userName, next.userName) {
			s.mu.Unlock()
			scimError(w, http.StatusConflict, "uniqueness", "userName already exists.")
			return
		}
	}
	next.id, next.created, next.modified, next.enrollment = cur.id, cur.created, s.now(), cur.enrollment
	events, err := s.reconcileLocked(next, cur)
	if err != nil {
		s.mu.Unlock()
		w.Header().Set("Retry-After", "30")
		scimError(w, http.StatusServiceUnavailable, "", "The issuer did not answer. Nothing was changed.")
		return
	}
	s.users[id] = next
	out := s.resourceLocked(next)
	s.mu.Unlock()
	s.notify(events)
	scimJSON(w, http.StatusOK, out)
}

func (s *Stub) scimDeleteUser(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	u, ok := s.users[r.PathValue("id")]
	if !ok {
		s.mu.Unlock()
		scimError(w, http.StatusNotFound, "", "No such user.")
		return
	}
	var events []cgcom.Event
	if rec := s.recs[u.enrollment]; rec != nil && s.cancelLocked(rec) {
		events = append(events, s.eventLocked(rec))
	}
	delete(s.users, u.id)
	for i, id := range s.uord {
		if id == u.id {
			s.uord = append(s.uord[:i], s.uord[i+1:]...)
			break
		}
	}
	s.mu.Unlock()
	s.notify(events)
	w.WriteHeader(http.StatusNoContent)
}

// reconcileLocked moves the enrolment of u to match it: an inactive user has
// no open enrolment; an active one has one for its current identifiers.
func (s *Stub) reconcileLocked(u, prev *scimUser) ([]cgcom.Event, error) {
	var events []cgcom.Event
	cur := s.recs[u.enrollment]
	changed := prev != nil && (prev.admin != u.admin || prev.coll != u.coll)
	if cur != nil && (!u.active || changed) {
		if s.cancelLocked(cur) {
			events = append(events, s.eventLocked(cur))
		}
		cur = nil
	}
	if !u.active || (cur != nil && !cur.e.State.Final()) {
		return events, nil
	}
	e, created, err := s.openLocked(u.admin, u.coll)
	if err != nil {
		return nil, err
	}
	u.enrollment = e.ID
	if created {
		events = append(events, s.eventLocked(s.recs[e.ID]))
	}
	return events, nil
}

func (s *Stub) eventLocked(rec *record) cgcom.Event {
	return cgcom.Event{EventID: newUUID(), Event: cgcom.EventStateChanged, OccurredAt: s.now(), Enrollment: rec.e}
}

// notify sends the webhooks in the background: the SCIM response must not
// wait for the organisation's receiver.
func (s *Stub) notify(events []cgcom.Event) {
	if len(events) == 0 {
		return
	}
	go func() {
		for _, ev := range events {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			s.SendEvent(ctx, ev)
			cancel()
		}
	}()
}

func (s *Stub) resourceLocked(u *scimUser) map[string]any {
	out := deepCopy(u.raw)
	out["schemas"] = []string{SchemaUser, SchemaExtension}
	out["id"] = u.id
	out["active"] = u.active
	ext, _ := out[SchemaExtension].(map[string]any)
	if ext == nil {
		ext = map[string]any{}
	}
	ext["collegiateNumber"], ext["administrativeNumber"] = u.coll, u.admin
	if rec := s.recs[u.enrollment]; rec != nil {
		ext["enrollmentId"], ext["enrollmentState"] = rec.e.ID, string(rec.e.State)
	}
	out[SchemaExtension] = ext
	out["meta"] = map[string]any{"resourceType": "User", "created": u.created.Format(time.RFC3339),
		"lastModified": u.modified.Format(time.RFC3339), "location": scimPrefix + "/Users/" + u.id}
	return out
}

// SCIMUsers returns the provisioned users, newest first, for the simulator.
func (s *Stub) SCIMUsers() []SCIMUser {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]SCIMUser, 0, len(s.uord))
	for i := len(s.uord) - 1; i >= 0; i-- {
		u := s.users[s.uord[i]]
		row := SCIMUser{ID: u.id, UserName: u.userName, CollegiateNumber: u.coll, Active: u.active, EnrollmentID: u.enrollment}
		row.DisplayName, _ = u.raw["displayName"].(string)
		if rec := s.recs[u.enrollment]; rec != nil {
			row.State = rec.e.State
		}
		out = append(out, row)
	}
	return out
}

// userFrom reads and validates a User representation. The read-only
// attributes of the extension are dropped.
func userFrom(in map[string]any) (*scimUser, string) {
	raw := deepCopy(in)
	delete(raw, "id")
	delete(raw, "meta")
	delete(raw, "schemas")
	u := &scimUser{raw: raw, active: true}
	u.userName, _ = raw["userName"].(string)
	u.externalID, _ = raw["externalId"].(string)
	if a, ok := raw["active"].(bool); ok {
		u.active = a
	}
	ext, _ := raw[SchemaExtension].(map[string]any)
	if ext != nil {
		delete(ext, "enrollmentId")
		delete(ext, "enrollmentState")
		u.coll, _ = ext["collegiateNumber"].(string)
		admin, _ := ext["administrativeNumber"].(string)
		u.admin = cgcom.NormaliseAdministrativeNumber(admin)
	}
	var problems []string
	if strings.TrimSpace(u.userName) == "" {
		problems = append(problems, "userName is required")
	}
	if !cgcom.ValidCollegiateNumber(u.coll) {
		problems = append(problems, SchemaExtension+":collegiateNumber must be 9 digits")
	}
	if !cgcom.ValidAdministrativeNumber(u.admin) {
		problems = append(problems, SchemaExtension+":administrativeNumber is required (DNI, NIE or passport)")
	}
	return u, strings.Join(problems, "; ")
}

// ----------------------------------------------------------------- groups

func (s *Stub) scimListGroups(w http.ResponseWriter, r *http.Request) {
	attr, value, err := parseFilter(r.URL.Query().Get("filter"))
	if err != nil {
		scimError(w, http.StatusBadRequest, "invalidFilter", err.Error())
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []any
	for _, g := range s.groups {
		if name, _ := g["displayName"].(string); attr == "displayname" && !strings.EqualFold(name, value) {
			continue
		}
		out = append(out, g)
	}
	scimJSON(w, http.StatusOK, listResponse(out, 1))
}

func (s *Stub) scimGetGroup(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.groups[r.PathValue("id")]
	if !ok {
		scimError(w, http.StatusNotFound, "", "No such group.")
		return
	}
	scimJSON(w, http.StatusOK, g)
}

func (s *Stub) scimPutGroup(w http.ResponseWriter, r *http.Request) {
	in, ok := decodeSCIM(w, r)
	if !ok {
		return
	}
	if name, _ := in["displayName"].(string); strings.TrimSpace(name) == "" {
		scimError(w, http.StatusBadRequest, "invalidValue", "displayName is required.")
		return
	}
	id, status := r.PathValue("id"), http.StatusOK
	s.mu.Lock()
	if id == "" {
		id, status = newUUID(), http.StatusCreated
	} else if _, ok := s.groups[id]; !ok {
		s.mu.Unlock()
		scimError(w, http.StatusNotFound, "", "No such group.")
		return
	}
	in["id"], in["schemas"] = id, []string{SchemaGroup}
	in["meta"] = map[string]any{"resourceType": "Group", "location": scimPrefix + "/Groups/" + id}
	if s.groups == nil {
		s.groups = map[string]map[string]any{}
	}
	s.groups[id] = in
	s.mu.Unlock()
	scimJSON(w, status, in)
}

func (s *Stub) scimDeleteGroup(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.groups[r.PathValue("id")]; !ok {
		scimError(w, http.StatusNotFound, "", "No such group.")
		return
	}
	delete(s.groups, r.PathValue("id"))
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------- helpers

func decodeSCIM(w http.ResponseWriter, r *http.Request) (map[string]any, bool) {
	var in map[string]any
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil || in == nil {
		scimError(w, http.StatusBadRequest, "invalidSyntax", "The body is not a JSON object.")
		return nil, false
	}
	return in, true
}

// parseFilter supports the one form provisioning clients use:
// <attribute> eq "<value>". It returns the attribute in lower case.
func parseFilter(f string) (attr, value string, err error) {
	f = strings.TrimSpace(f)
	if f == "" {
		return "", "", nil
	}
	parts := strings.SplitN(f, " ", 3)
	if len(parts) != 3 || !strings.EqualFold(parts[1], "eq") {
		return "", "", fmt.Errorf("only <attribute> eq \"<value>\" is supported")
	}
	v, err := strconv.Unquote(parts[2])
	if err != nil {
		return "", "", fmt.Errorf("the value must be a quoted string")
	}
	attr = strings.ToLower(parts[0])
	switch attr {
	case "username", "externalid", "displayname":
		return attr, v, nil
	}
	return "", "", fmt.Errorf("filtering by %s is not supported", parts[0])
}

// applyPatch applies one PatchOp operation. Paths are simple attribute
// names, optionally prefixed by the extension URN ("urn:...:collegiateNumber").
func applyPatch(doc map[string]any, op map[string]any) error {
	kind, _ := op["op"].(string)
	path, _ := op["path"].(string)
	kind = strings.ToLower(kind)
	if kind != "add" && kind != "replace" && kind != "remove" {
		return fmt.Errorf("unsupported op %q", kind)
	}
	target, key := doc, path
	if strings.HasPrefix(path, SchemaExtension+":") {
		ext, _ := doc[SchemaExtension].(map[string]any)
		if ext == nil {
			ext = map[string]any{}
			doc[SchemaExtension] = ext
		}
		target, key = ext, strings.TrimPrefix(path, SchemaExtension+":")
	} else if strings.ContainsAny(path, "[.") {
		return fmt.Errorf("path %q is not supported", path)
	}
	switch {
	case kind == "remove":
		delete(target, key)
	case key == "":
		vals, ok := op["value"].(map[string]any)
		if !ok {
			return fmt.Errorf("an operation without path needs an object value")
		}
		for k, v := range vals {
			if sub, ok := v.(map[string]any); ok && k == SchemaExtension {
				ext, _ := doc[SchemaExtension].(map[string]any)
				if ext == nil {
					ext = map[string]any{}
				}
				for ek, ev := range sub {
					ext[ek] = ev
				}
				doc[k] = ext
				continue
			}
			doc[k] = v
		}
	default:
		target[key] = op["value"]
	}
	// Some clients send booleans as strings.
	if a, ok := doc["active"].(string); ok {
		doc["active"] = strings.EqualFold(a, "true")
	}
	return nil
}

func deepCopy(m map[string]any) map[string]any {
	b, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	if out == nil {
		out = map[string]any{}
	}
	return out
}

func listResponse(res []any, start int) map[string]any {
	if res == nil {
		res = []any{}
	}
	return map[string]any{"schemas": []string{schemaList}, "totalResults": len(res), "startIndex": start,
		"itemsPerPage": len(res), "Resources": res}
}

func scimJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func scimError(w http.ResponseWriter, status int, scimType, detail string) {
	body := map[string]any{"schemas": []string{schemaError}, "status": strconv.Itoa(status), "detail": detail}
	if scimType != "" {
		body["scimType"] = scimType
	}
	scimJSON(w, status, body)
}
