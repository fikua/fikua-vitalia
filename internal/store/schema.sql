-- Physicians the clinic works with. Synthetic data only.
CREATE TABLE IF NOT EXISTS practitioners (
  id                    INTEGER PRIMARY KEY,
  full_name             TEXT NOT NULL,
  administrative_number TEXT NOT NULL,
  collegiate_number     TEXT NOT NULL,
  specialty             TEXT NOT NULL DEFAULT '',
  email                 TEXT NOT NULL DEFAULT '',
  created_at            TEXT NOT NULL,
  UNIQUE (administrative_number, collegiate_number)
);

-- Enrolments as the adapter last reported them. The id is the adapter's.
CREATE TABLE IF NOT EXISTS enrollments (
  id                       TEXT PRIMARY KEY,
  practitioner_id          INTEGER NOT NULL REFERENCES practitioners(id),
  state                    TEXT NOT NULL,
  body                     TEXT NOT NULL,
  adapter_updated_at       TEXT NOT NULL DEFAULT '',
  invalidated_reason       TEXT NOT NULL DEFAULT '',
  invalidated_procedure_id TEXT NOT NULL DEFAULT '',
  invalidated_at           TEXT NOT NULL DEFAULT '',
  created_at               TEXT NOT NULL,
  synced_at                TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS enrollments_practitioner ON enrollments (practitioner_id, created_at);

-- Every request that reached the webhook endpoint, valid or not.
CREATE TABLE IF NOT EXISTS webhook_events (
  id              INTEGER PRIMARY KEY,
  event_id        TEXT UNIQUE,
  received_at     TEXT NOT NULL,
  signature_valid INTEGER NOT NULL,
  signature_error TEXT NOT NULL DEFAULT '',
  event           TEXT NOT NULL DEFAULT '',
  enrollment_id   TEXT NOT NULL DEFAULT '',
  occurred_at     TEXT NOT NULL DEFAULT '',
  raw_body        TEXT NOT NULL,
  status          TEXT NOT NULL,
  status_detail   TEXT NOT NULL DEFAULT '',
  processed_at    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS webhook_events_enrollment ON webhook_events (enrollment_id);
CREATE INDEX IF NOT EXISTS webhook_events_status ON webhook_events (status);

-- Every call to the adapter: the main evidence for phase 2.
CREATE TABLE IF NOT EXISTS adapter_calls (
  id            INTEGER PRIMARY KEY,
  at            TEXT NOT NULL,
  operation     TEXT NOT NULL,
  method        TEXT NOT NULL,
  path          TEXT NOT NULL,
  request_body  TEXT NOT NULL DEFAULT '',
  status        INTEGER NOT NULL DEFAULT 0,
  problem_type  TEXT NOT NULL DEFAULT '',
  response_body TEXT NOT NULL DEFAULT '',
  retry_after   TEXT NOT NULL DEFAULT '',
  duration_ms   INTEGER NOT NULL DEFAULT 0,
  error         TEXT NOT NULL DEFAULT '',
  enrollment_id TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS adapter_calls_enrollment ON adapter_calls (enrollment_id);
