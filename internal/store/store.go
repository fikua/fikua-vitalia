// Package store keeps the platform's data in PostgreSQL (the platform cluster,
// schema "vitalia", see fikua-platform-iac).
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fikua/fikua-vitalia/internal/cgcom"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
)

//go:embed migrations/*.sql
var migrations embed.FS

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// Store wraps the database.
type Store struct {
	db  conn
	now func() time.Time
}

// Open connects to Postgres with the given URL (the role's search_path selects
// the schema) and applies the embedded migrations.
func Open(ctx context.Context, databaseURL string) (*Store, error) {
	raw, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	raw.SetMaxOpenConns(10)
	raw.SetMaxIdleConns(5)
	raw.SetConnMaxLifetime(30 * time.Minute)
	if err := raw.PingContext(ctx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	if err := migrate(ctx, raw); err != nil {
		raw.Close()
		return nil, err
	}
	return &Store{db: conn{raw}, now: time.Now}, nil
}

// migrate applies, in name order, every embedded migration not applied yet.
// Each one runs in its own transaction; an advisory lock keeps two processes
// (for example two replicas starting together) from migrating at once.
func migrate(ctx context.Context, db *sql.DB) error {
	c, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire connection: %w", err)
	}
	defer c.Close()

	const lockID = 7_310_243
	if _, err := c.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, lockID); err != nil {
		return fmt.Errorf("take migration lock: %w", err)
	}
	defer c.ExecContext(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, lockID)

	if _, err := c.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		var applied bool
		if err := c.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE name = $1)`, name).Scan(&applied); err != nil {
			return fmt.Errorf("check migration %s: %w", name, err)
		}
		if applied {
			continue
		}
		body, err := migrations.ReadFile(name)
		if err != nil {
			return err
		}
		tx, err := c.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			tx.Rollback()
			return fmt.Errorf("apply migration %s: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (name) VALUES ($1)`, name); err != nil {
			tx.Rollback()
			return fmt.Errorf("record migration %s: %w", name, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %s: %w", name, err)
		}
	}
	return nil
}

// conn lets the queries below keep their portable "?" placeholders: every
// statement is rewritten to Postgres' $1, $2, ... before it is sent.
type conn struct{ *sql.DB }

func (c conn) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	return c.DB.ExecContext(ctx, rebind(q), args...)
}

func (c conn) QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	return c.DB.QueryContext(ctx, rebind(q), args...)
}

func (c conn) QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row {
	return c.DB.QueryRowContext(ctx, rebind(q), args...)
}

func (c conn) BeginTx(ctx context.Context, opts *sql.TxOptions) (txn, error) {
	t, err := c.DB.BeginTx(ctx, opts)
	return txn{t}, err
}

type txn struct{ *sql.Tx }

func (t txn) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	return t.Tx.ExecContext(ctx, rebind(q), args...)
}

func (t txn) QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row {
	return t.Tx.QueryRowContext(ctx, rebind(q), args...)
}

// rebind turns "?" placeholders into $1, $2, ... None of the statements has a
// "?" inside a string literal.
func rebind(q string) string {
	if !strings.Contains(q, "?") {
		return q
	}
	var b strings.Builder
	n := 0
	for _, r := range q {
		if r == '?' {
			n++
			b.WriteString("$" + strconv.Itoa(n))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Ping checks the database for the health endpoint.
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func parseTS(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}

// ---------------------------------------------------------------- practitioners

// Practitioner is a physician of the clinic.
type Practitioner struct {
	ID                   int64
	FullName             string
	AdministrativeNumber string
	CollegiateNumber     string
	Specialty            string
	Email                string
	CreatedAt            time.Time
	DoctorIDIssuer       string // bound on the first DoctorID login
	DoctorIDSubject      string
}

// FindOrCreatePractitioner returns the practitioner with that pair, creating
// it with the given details when it does not exist. Two concurrent calls for
// the same pair both get the one row: the INSERT does nothing on conflict and
// the existing row is read instead.
func (s *Store) FindOrCreatePractitioner(ctx context.Context, p Practitioner) (Practitioner, error) {
	existing, err := s.practitionerByPair(ctx, p.AdministrativeNumber, p.CollegiateNumber)
	if err == nil {
		return existing, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return Practitioner{}, err
	}
	p.CreatedAt = s.now().UTC()
	err = s.db.QueryRowContext(ctx,
		`INSERT INTO practitioners (full_name, administrative_number, collegiate_number, specialty, email, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT (administrative_number, collegiate_number) DO NOTHING
		 RETURNING id`,
		p.FullName, p.AdministrativeNumber, p.CollegiateNumber, p.Specialty, p.Email, ts(p.CreatedAt)).Scan(&p.ID)
	if errors.Is(err, sql.ErrNoRows) {
		return s.practitionerByPair(ctx, p.AdministrativeNumber, p.CollegiateNumber)
	}
	if err != nil {
		return Practitioner{}, fmt.Errorf("insert practitioner: %w", err)
	}
	return p, nil
}

func (s *Store) practitionerByPair(ctx context.Context, admin, coll string) (Practitioner, error) {
	return s.scanPractitioner(s.db.QueryRowContext(ctx, practitionerSelect+` WHERE administrative_number = ? AND collegiate_number = ?`, admin, coll))
}

// Practitioner returns one practitioner.
func (s *Store) Practitioner(ctx context.Context, id int64) (Practitioner, error) {
	return s.scanPractitioner(s.db.QueryRowContext(ctx, practitionerSelect+` WHERE id = ?`, id))
}

const practitionerSelect = `SELECT id, full_name, administrative_number, collegiate_number, specialty, email, created_at,
	doctorid_iss, doctorid_sub FROM practitioners`

func (s *Store) scanPractitioner(row *sql.Row) (Practitioner, error) {
	var p Practitioner
	var created string
	err := row.Scan(&p.ID, &p.FullName, &p.AdministrativeNumber, &p.CollegiateNumber, &p.Specialty, &p.Email, &created,
		&p.DoctorIDIssuer, &p.DoctorIDSubject)
	if errors.Is(err, sql.ErrNoRows) {
		return Practitioner{}, ErrNotFound
	}
	if err != nil {
		return Practitioner{}, fmt.Errorf("read practitioner: %w", err)
	}
	p.CreatedAt = parseTS(created)
	return p, nil
}

// PractitionerRow is a practitioner with its latest enrolment, for the list.
type PractitionerRow struct {
	Practitioner
	Latest *Enrollment
}

// ListPractitioners returns every practitioner with its latest enrolment,
// most recently active first.
func (s *Store) ListPractitioners(ctx context.Context) ([]PractitionerRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT p.id, p.full_name, p.administrative_number, p.collegiate_number, p.specialty, p.email, p.created_at,
		       p.doctorid_iss, p.doctorid_sub, e.id, e.state, e.body, e.adapter_updated_at, e.invalidated_reason, e.invalidated_procedure_id,
		       e.invalidated_at, e.created_at, e.synced_at
		FROM practitioners p
		LEFT JOIN enrollments e ON e.id = (
			SELECT id FROM enrollments WHERE practitioner_id = p.id ORDER BY created_at DESC LIMIT 1)
		ORDER BY COALESCE(e.synced_at, p.created_at) DESC`)
	if err != nil {
		return nil, fmt.Errorf("list practitioners: %w", err)
	}
	defer rows.Close()
	var out []PractitionerRow
	for rows.Next() {
		var r PractitionerRow
		var created string
		var eid, state, body, upd, invR, invP, invAt, eCreated, synced sql.NullString
		if err := rows.Scan(&r.ID, &r.FullName, &r.AdministrativeNumber, &r.CollegiateNumber, &r.Specialty, &r.Email, &created,
			&r.DoctorIDIssuer, &r.DoctorIDSubject, &eid, &state, &body, &upd, &invR, &invP, &invAt, &eCreated, &synced); err != nil {
			return nil, fmt.Errorf("scan practitioner: %w", err)
		}
		r.CreatedAt = parseTS(created)
		if eid.Valid {
			e := Enrollment{
				ID: eid.String, PractitionerID: r.ID, State: cgcom.State(state.String), Body: body.String,
				AdapterUpdatedAt: upd.String, InvalidatedReason: invR.String, InvalidatedProcedureID: invP.String,
				InvalidatedAt: parseTS(invAt.String), CreatedAt: parseTS(eCreated.String), SyncedAt: parseTS(synced.String),
			}
			r.Latest = &e
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ------------------------------------------------------------------ enrollments

// Enrollment is the stored copy of an adapter enrolment.
type Enrollment struct {
	ID                     string
	PractitionerID         int64
	State                  cgcom.State
	Body                   string
	AdapterUpdatedAt       string
	InvalidatedReason      string
	InvalidatedProcedureID string
	InvalidatedAt          time.Time
	CreatedAt              time.Time
	SyncedAt               time.Time
}

// Decoded parses the stored body.
func (e Enrollment) Decoded() cgcom.Enrollment {
	d, _ := cgcom.DecodeEnrollment([]byte(e.Body))
	return d
}

// enrollmentLockSpace is the first key of the per-enrolment advisory locks.
const enrollmentLockSpace = 7_310_246

// Upsert outcome.
const (
	Applied = "applied"
	Stale   = "stale"
)

// UpsertEnrollment stores what the adapter reported. With authoritative (a
// response to our own call, or a GET) it always wins. Otherwise (a webhook)
// it is only applied when its updated_at is not older than the stored one,
// so a late or out-of-order webhook does not move the state backwards.
func (s *Store) UpsertEnrollment(ctx context.Context, practitionerID int64, e cgcom.Enrollment, raw []byte, authoritative bool) (string, error) {
	now := ts(s.now())
	upd := ""
	if e.UpdatedAt != nil {
		upd = ts(*e.UpdatedAt)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	// One writer per enrolment at a time (a webhook and our own call can race):
	// without it both could read "not stored" and insert, or both pass the
	// staleness check and the older one win. Released at COMMIT/ROLLBACK.
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(?, hashtext(?))`, enrollmentLockSpace, e.ID); err != nil {
		return "", fmt.Errorf("lock enrollment: %w", err)
	}

	var storedUpd string
	err = tx.QueryRowContext(ctx, `SELECT adapter_updated_at FROM enrollments WHERE id = ?`, e.ID).Scan(&storedUpd)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if practitionerID == 0 {
			return "", ErrNotFound
		}
		_, err = tx.ExecContext(ctx,
			`INSERT INTO enrollments (id, practitioner_id, state, body, adapter_updated_at, created_at, synced_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`, e.ID, practitionerID, string(e.State), string(raw), upd, now, now)
		if err != nil {
			return "", fmt.Errorf("insert enrollment: %w", err)
		}
	case err != nil:
		return "", fmt.Errorf("read enrollment: %w", err)
	default:
		if !authoritative && storedUpd != "" && upd != "" && parseTS(upd).Before(parseTS(storedUpd)) {
			return Stale, tx.Commit()
		}
		_, err = tx.ExecContext(ctx,
			`UPDATE enrollments SET state = ?, body = ?, adapter_updated_at = ?, synced_at = ? WHERE id = ?`,
			string(e.State), string(raw), upd, now, e.ID)
		if err != nil {
			return "", fmt.Errorf("update enrollment: %w", err)
		}
	}
	// A new DoctorID clears a previous invalidation notice.
	if e.DoctorID != nil && e.DoctorID.ProcedureID != "" {
		_, err = tx.ExecContext(ctx,
			`UPDATE enrollments SET invalidated_reason = '', invalidated_procedure_id = '', invalidated_at = ''
			 WHERE id = ? AND invalidated_procedure_id != '' AND invalidated_procedure_id != ?`, e.ID, e.DoctorID.ProcedureID)
		if err != nil {
			return "", fmt.Errorf("clear invalidation: %w", err)
		}
	}
	return Applied, tx.Commit()
}

// MarkInvalidated records a doctorid_invalidated notice.
func (s *Store) MarkInvalidated(ctx context.Context, id, reason, procedureID string, at time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE enrollments SET invalidated_reason = ?, invalidated_procedure_id = ?, invalidated_at = ? WHERE id = ?`,
		reason, procedureID, ts(at), id)
	return err
}

const enrollmentSelect = `SELECT id, practitioner_id, state, body, adapter_updated_at, invalidated_reason,
	invalidated_procedure_id, invalidated_at, created_at, synced_at FROM enrollments`

// Enrollment returns one stored enrolment.
func (s *Store) Enrollment(ctx context.Context, id string) (Enrollment, error) {
	rows, err := s.db.QueryContext(ctx, enrollmentSelect+` WHERE id = ?`, id)
	if err != nil {
		return Enrollment{}, err
	}
	list, err := scanEnrollments(rows)
	if err != nil {
		return Enrollment{}, err
	}
	if len(list) == 0 {
		return Enrollment{}, ErrNotFound
	}
	return list[0], nil
}

// EnrollmentsOf returns a practitioner's enrolments, newest first.
func (s *Store) EnrollmentsOf(ctx context.Context, practitionerID int64) ([]Enrollment, error) {
	rows, err := s.db.QueryContext(ctx, enrollmentSelect+` WHERE practitioner_id = ? ORDER BY created_at DESC`, practitionerID)
	if err != nil {
		return nil, err
	}
	return scanEnrollments(rows)
}

func scanEnrollments(rows *sql.Rows) ([]Enrollment, error) {
	defer rows.Close()
	var out []Enrollment
	for rows.Next() {
		var e Enrollment
		var state, invAt, created, synced string
		if err := rows.Scan(&e.ID, &e.PractitionerID, &state, &e.Body, &e.AdapterUpdatedAt, &e.InvalidatedReason,
			&e.InvalidatedProcedureID, &invAt, &created, &synced); err != nil {
			return nil, fmt.Errorf("scan enrollment: %w", err)
		}
		e.State = cgcom.State(state)
		e.InvalidatedAt, e.CreatedAt, e.SyncedAt = parseTS(invAt), parseTS(created), parseTS(synced)
		out = append(out, e)
	}
	return out, rows.Err()
}

// --------------------------------------------------------------- webhook events

// Webhook event processing status.
const (
	WebhookRejected          = "rejected"           // bad signature: body not processed
	WebhookInvalid           = "invalid"            // signed but not a valid event
	WebhookPending           = "pending"            // stored, waiting for the processor
	WebhookApplied           = "applied"            // applied to the enrolment
	WebhookStale             = "stale"              // older than what we have
	WebhookUnknownEnrollment = "unknown_enrollment" // enrolment not known (yet)
	WebhookIgnored           = "ignored"            // event type we do not handle
	WebhookError             = "error"
)

// WebhookEvent is one request to the webhook endpoint.
type WebhookEvent struct {
	ID             int64
	EventID        string // empty when rejected
	ReceivedAt     time.Time
	SignatureValid bool
	SignatureError string
	Event          string
	EnrollmentID   string
	OccurredAt     string
	RawBody        string
	Status         string
	StatusDetail   string
	ProcessedAt    time.Time
}

// RecordWebhook stores a received request. For a signed event whose
// event_id is already stored it stores nothing and reports a duplicate.
func (s *Store) RecordWebhook(ctx context.Context, ev WebhookEvent) (duplicate bool, err error) {
	var eventID any
	if ev.EventID != "" {
		eventID = ev.EventID
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO webhook_events (event_id, received_at, signature_valid, signature_error, event, enrollment_id,
			occurred_at, raw_body, status, status_detail)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (event_id) DO NOTHING`,
		eventID, ts(ev.ReceivedAt), ev.SignatureValid, ev.SignatureError, ev.Event, ev.EnrollmentID,
		ev.OccurredAt, ev.RawBody, ev.Status, ev.StatusDetail)
	if err != nil {
		return false, fmt.Errorf("insert webhook event: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 0, nil
}

// WebhooksToProcess returns events the processor still has to apply,
// oldest first: new ones and those whose enrolment was not known.
func (s *Store) WebhooksToProcess(ctx context.Context, limit int) ([]WebhookEvent, error) {
	return s.queryWebhooks(ctx, ` WHERE status IN (?, ?) ORDER BY id ASC LIMIT ?`, WebhookPending, WebhookUnknownEnrollment, limit)
}

// WebhooksOf returns the events of one enrolment, newest first.
func (s *Store) WebhooksOf(ctx context.Context, enrollmentID string) ([]WebhookEvent, error) {
	return s.queryWebhooks(ctx, ` WHERE enrollment_id = ? ORDER BY id DESC`, enrollmentID)
}

// RecentWebhooks returns the latest events of any kind.
func (s *Store) RecentWebhooks(ctx context.Context, limit int) ([]WebhookEvent, error) {
	return s.queryWebhooks(ctx, ` ORDER BY id DESC LIMIT ?`, limit)
}

// SetWebhookStatus records the processing outcome.
func (s *Store) SetWebhookStatus(ctx context.Context, id int64, status, detail string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE webhook_events SET status = ?, status_detail = ?, processed_at = ? WHERE id = ?`,
		status, detail, ts(s.now()), id)
	return err
}

func (s *Store) queryWebhooks(ctx context.Context, where string, args ...any) ([]WebhookEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, COALESCE(event_id, ''), received_at, signature_valid, signature_error,
		event, enrollment_id, occurred_at, raw_body, status, status_detail, processed_at FROM webhook_events`+where, args...)
	if err != nil {
		return nil, fmt.Errorf("query webhook events: %w", err)
	}
	defer rows.Close()
	var out []WebhookEvent
	for rows.Next() {
		var ev WebhookEvent
		var received, processed string
		if err := rows.Scan(&ev.ID, &ev.EventID, &received, &ev.SignatureValid, &ev.SignatureError, &ev.Event,
			&ev.EnrollmentID, &ev.OccurredAt, &ev.RawBody, &ev.Status, &ev.StatusDetail, &processed); err != nil {
			return nil, fmt.Errorf("scan webhook event: %w", err)
		}
		ev.ReceivedAt, ev.ProcessedAt = parseTS(received), parseTS(processed)
		out = append(out, ev)
	}
	return out, rows.Err()
}

// ----------------------------------------------------------------- adapter calls

// RecordCall stores a call to the adapter (cgcom.CallRecorder).
func (s *Store) RecordCall(ctx context.Context, c cgcom.Call) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO adapter_calls (at, operation, method, path, request_body, status, problem_type, response_body,
			retry_after, duration_ms, error, enrollment_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ts(c.At), c.Operation, c.Method, c.Path, c.RequestBody, c.Status, c.ProblemType, c.ResponseBody,
		c.RetryAfter, c.Duration.Milliseconds(), c.Error, c.EnrollmentID)
	return err
}

// CallsOf returns the calls about one enrolment, newest first.
func (s *Store) CallsOf(ctx context.Context, enrollmentID string) ([]cgcom.Call, error) {
	return s.queryCalls(ctx, ` WHERE enrollment_id = ? ORDER BY id DESC`, enrollmentID)
}

// RecentCalls returns the latest calls.
func (s *Store) RecentCalls(ctx context.Context, limit int) ([]cgcom.Call, error) {
	return s.queryCalls(ctx, ` ORDER BY id DESC LIMIT ?`, limit)
}

func (s *Store) queryCalls(ctx context.Context, where string, args ...any) ([]cgcom.Call, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT at, operation, method, path, request_body, status, problem_type,
		response_body, retry_after, duration_ms, error, enrollment_id FROM adapter_calls`+where, args...)
	if err != nil {
		return nil, fmt.Errorf("query calls: %w", err)
	}
	defer rows.Close()
	var out []cgcom.Call
	for rows.Next() {
		var c cgcom.Call
		var at string
		var ms int64
		if err := rows.Scan(&at, &c.Operation, &c.Method, &c.Path, &c.RequestBody, &c.Status, &c.ProblemType,
			&c.ResponseBody, &c.RetryAfter, &ms, &c.Error, &c.EnrollmentID); err != nil {
			return nil, fmt.Errorf("scan call: %w", err)
		}
		c.At, c.Duration = parseTS(at), time.Duration(ms)*time.Millisecond
		out = append(out, c)
	}
	return out, rows.Err()
}

// BindDoctorID records the DoctorID identity of a practitioner on their first
// login. It never overwrites an existing binding.
func (s *Store) BindDoctorID(ctx context.Context, practitionerID int64, iss, sub string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE practitioners SET doctorid_iss = ?, doctorid_sub = ? WHERE id = ? AND doctorid_sub = ''`, iss, sub, practitionerID)
	return err
}

// ResetDoctorIDBinding forgets the bound DoctorID identity, so the next
// login binds again (for example, after the physician's DoctorID changed).
func (s *Store) ResetDoctorIDBinding(ctx context.Context, practitionerID int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE practitioners SET doctorid_iss = '', doctorid_sub = '' WHERE id = ?`, practitionerID)
	return err
}

// ---------------------------------------------------------------- login events

// Login outcomes.
const (
	LoginGranted = "granted"
	LoginDenied  = "denied"
)

// LoginEvent is one attempt to enter with DoctorID.
type LoginEvent struct {
	At               time.Time
	Outcome          string
	Reason           string
	PractitionerID   int64
	CollegiateNumber string
	Subject          string
	ACR              string
	AMR              string
	Claims           string
	Detail           string
}

// RecordLogin stores a login attempt.
func (s *Store) RecordLogin(ctx context.Context, e LoginEvent) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO login_events (at, outcome, reason, practitioner_id, collegiate_number,
		subject, acr, amr, claims, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ts(e.At), e.Outcome, e.Reason, e.PractitionerID, e.CollegiateNumber, e.Subject, e.ACR, e.AMR, e.Claims, e.Detail)
	return err
}

// LoginsOf returns a practitioner's login attempts, newest first.
func (s *Store) LoginsOf(ctx context.Context, practitionerID int64) ([]LoginEvent, error) {
	return s.queryLogins(ctx, ` WHERE practitioner_id = ? ORDER BY id DESC LIMIT 50`, practitionerID)
}

// RecentLogins returns the latest login attempts.
func (s *Store) RecentLogins(ctx context.Context, limit int) ([]LoginEvent, error) {
	return s.queryLogins(ctx, ` ORDER BY id DESC LIMIT ?`, limit)
}

func (s *Store) queryLogins(ctx context.Context, where string, args ...any) ([]LoginEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT at, outcome, reason, practitioner_id, collegiate_number, subject, acr, amr,
		claims, detail FROM login_events`+where, args...)
	if err != nil {
		return nil, fmt.Errorf("query logins: %w", err)
	}
	defer rows.Close()
	var out []LoginEvent
	for rows.Next() {
		var e LoginEvent
		var at string
		if err := rows.Scan(&at, &e.Outcome, &e.Reason, &e.PractitionerID, &e.CollegiateNumber, &e.Subject, &e.ACR,
			&e.AMR, &e.Claims, &e.Detail); err != nil {
			return nil, fmt.Errorf("scan login: %w", err)
		}
		e.At = parseTS(at)
		out = append(out, e)
	}
	return out, rows.Err()
}
