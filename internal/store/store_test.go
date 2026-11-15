package store_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/fikua/fikua-vitalia/internal/cgcom"
	"github.com/fikua/fikua-vitalia/internal/store"
	"github.com/fikua/fikua-vitalia/internal/store/storetest"
)

// SQLite serialised every write (one connection). PostgreSQL does not: these
// check that the read-then-write paths stay correct under concurrency.

func TestFindOrCreatePractitioner_Concurrent_OneRow(t *testing.T) {
	st := storetest.Open(t)
	ctx := context.Background()
	const n = 8

	ids := make([]int64, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, err := st.FindOrCreatePractitioner(ctx, store.Practitioner{
				FullName: "Laia Puig", AdministrativeNumber: "A1", CollegiateNumber: "280000101"})
			ids[i], errs[i] = p.ID, err
		}()
	}
	wg.Wait()
	for i := range n {
		if errs[i] != nil {
			t.Fatalf("call %d: %v", i, errs[i])
		}
		if ids[i] == 0 || ids[i] != ids[0] {
			t.Fatalf("call %d got id %d, call 0 got %d: want one practitioner", i, ids[i], ids[0])
		}
	}
	list, err := st.ListPractitioners(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("%d practitioners stored, want 1", len(list))
	}
}

func TestUpsertEnrollment_Concurrent_NewestWins(t *testing.T) {
	st := storetest.Open(t)
	ctx := context.Background()
	p, err := st.FindOrCreatePractitioner(ctx, store.Practitioner{
		FullName: "Laia Puig", AdministrativeNumber: "A1", CollegiateNumber: "280000101"})
	if err != nil {
		t.Fatal(err)
	}

	const id = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	base := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	const n = 10
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			upd := base.Add(time.Duration(i) * time.Minute)
			state := cgcom.State("STATE_" + string(rune('A'+i)))
			e := cgcom.Enrollment{ID: id, State: state, UpdatedAt: &upd}
			// Webhooks (not authoritative): an older one must never overwrite a newer one.
			_, errs[i] = st.UpsertEnrollment(ctx, p.ID, e, []byte(`{}`), false)
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("upsert %d: %v", i, err)
		}
	}
	got, err := st.Enrollment(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if want := cgcom.State("STATE_" + string(rune('A'+n-1))); got.State != want {
		t.Fatalf("stored state %q, want the newest %q", got.State, want)
	}
}
