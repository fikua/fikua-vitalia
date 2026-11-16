package store_test

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/log/logtest"

	"github.com/fikua/fikua-vitalia/internal/cgcom"
	"github.com/fikua/fikua-vitalia/internal/store"
	"github.com/fikua/fikua-vitalia/internal/store/storetest"
)

// enrollment.status_changed is emitted only when a stored enrolment really
// moves to another state, never on the first insert or a repeated state.
func TestUpsertEnrollment_AuditsOnlyStateChanges(t *testing.T) {
	st := storetest.Open(t)
	rec := logtest.NewRecorder()
	prev := global.GetLoggerProvider()
	global.SetLoggerProvider(rec)
	t.Cleanup(func() { global.SetLoggerProvider(prev) })

	ctx := context.Background()
	p, err := st.FindOrCreatePractitioner(ctx, store.Practitioner{
		FullName: "Laia Puig", AdministrativeNumber: "A2", CollegiateNumber: "280000102"})
	if err != nil {
		t.Fatal(err)
	}
	const id = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
	at := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	for i, state := range []cgcom.State{cgcom.Initiated, cgcom.Initiated, cgcom.PendingConfirmation} {
		upd := at.Add(time.Duration(i) * time.Minute)
		if _, err := st.UpsertEnrollment(ctx, p.ID, cgcom.Enrollment{ID: id, State: state, UpdatedAt: &upd}, []byte(`{}`), true); err != nil {
			t.Fatal(err)
		}
	}

	var got []map[string]string
	for _, records := range rec.Result() {
		for _, r := range records {
			m := map[string]string{}
			for _, kv := range r.Attributes {
				m[string(kv.Key)] = kv.Value.Emit()
			}
			got = append(got, m)
		}
	}
	if len(got) != 1 {
		t.Fatalf("audit records = %d (%v), want 1", len(got), got)
	}
	r := got[0]
	if r["event.domain"] != "audit" || r["event.name"] != "enrollment.status_changed" ||
		r["enrollment.id"] != id || r["status"] != string(cgcom.PendingConfirmation) || len(r) != 4 {
		t.Errorf("record = %v", r)
	}
}
