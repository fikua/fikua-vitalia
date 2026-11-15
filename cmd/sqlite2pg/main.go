// Command sqlite2pg copies a Vitalia SQLite database into the PostgreSQL schema
// (one-off, for the move to the platform cluster).
//
//	sqlite2pg -sqlite /data/vitalia.db -pg "$VITALIA_DATABASE_URL"
//
// Run it with the application stopped, on a file nobody writes to. It creates
// the schema (the application's own migrations), refuses to touch a target that
// already has rows, copies every table in one transaction, resets the identity
// counters and compares the row counts before committing. Nothing is deleted
// from the SQLite file.
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/fikua/fikua-vitalia/internal/store"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

// tables in foreign-key order; bools lists the columns SQLite stored as 0/1.
var tables = []struct {
	name  string
	ident bool
	bools []string
}{
	{"practitioners", true, nil},
	{"enrollments", false, nil},
	{"webhook_events", true, []string{"signature_valid"}},
	{"adapter_calls", true, nil},
	{"login_events", true, nil},
}

func main() {
	sqlitePath := flag.String("sqlite", "", "path of the SQLite database (a copy, or the file with the app stopped)")
	pgURL := flag.String("pg", os.Getenv("VITALIA_DATABASE_URL"), "PostgreSQL URL (default $VITALIA_DATABASE_URL)")
	flag.Parse()
	if *sqlitePath == "" || *pgURL == "" {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(context.Background(), *sqlitePath, *pgURL); err != nil {
		log.Fatalf("sqlite2pg: %v", err)
	}
}

func run(ctx context.Context, sqlitePath, pgURL string) error {
	if _, err := os.Stat(sqlitePath); err != nil {
		return err
	}
	src, err := sql.Open("sqlite", "file:"+sqlitePath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	defer src.Close()

	// Applies the schema migrations of the application.
	st, err := store.Open(ctx, pgURL)
	if err != nil {
		return err
	}
	st.Close()
	dst, err := sql.Open("pgx", pgURL)
	if err != nil {
		return err
	}
	defer dst.Close()

	for _, t := range tables {
		var n int
		if err := dst.QueryRowContext(ctx, "SELECT count(*) FROM "+t.name).Scan(&n); err != nil {
			return fmt.Errorf("count target %s: %w", t.name, err)
		}
		if n != 0 {
			return fmt.Errorf("target table %s already has %d rows: refusing to copy over it", t.name, n)
		}
	}

	tx, err := dst.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, t := range tables {
		copied, err := copyTable(ctx, src, tx, t.name, t.bools)
		if err != nil {
			return fmt.Errorf("%s: %w", t.name, err)
		}
		var want int
		if err := src.QueryRowContext(ctx, "SELECT count(*) FROM "+t.name).Scan(&want); err != nil {
			return err
		}
		var got int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM "+t.name).Scan(&got); err != nil {
			return err
		}
		if want != copied || got != want {
			return fmt.Errorf("%s: sqlite has %d rows, copied %d, postgres has %d", t.name, want, copied, got)
		}
		if t.ident {
			if _, err := tx.ExecContext(ctx, fmt.Sprintf(
				`SELECT setval(pg_get_serial_sequence('%s', 'id'), COALESCE(MAX(id), 1), MAX(id) IS NOT NULL) FROM %s`, t.name, t.name)); err != nil {
				return fmt.Errorf("reset identity of %s: %w", t.name, err)
			}
		}
		log.Printf("%-16s %6d rows", t.name, copied)
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	log.Print("done: every table copied and counted")
	return nil
}

func copyTable(ctx context.Context, src *sql.DB, tx *sql.Tx, table string, bools []string) (int, error) {
	rows, err := src.QueryContext(ctx, "SELECT * FROM "+table+" ORDER BY rowid")
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return 0, err
	}
	isBool := make([]bool, len(cols))
	for i, c := range cols {
		for _, b := range bools {
			isBool[i] = isBool[i] || b == c
		}
	}
	marks := make([]string, len(cols))
	for i := range marks {
		marks[i] = fmt.Sprintf("$%d", i+1)
	}
	// OVERRIDING SYSTEM VALUE: keep the original ids of the identity columns.
	insert := fmt.Sprintf("INSERT INTO %s (%s) OVERRIDING SYSTEM VALUE VALUES (%s)", table, strings.Join(cols, ", "), strings.Join(marks, ", "))
	stmt, err := tx.PrepareContext(ctx, insert)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	n := 0
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return n, err
		}
		for i, v := range vals {
			switch x := v.(type) {
			case []byte:
				vals[i] = string(x)
			case int64:
				if isBool[i] {
					vals[i] = x != 0
				}
			}
		}
		if _, err := stmt.ExecContext(ctx, vals...); err != nil {
			return n, fmt.Errorf("row %d: %w", n+1, err)
		}
		n++
	}
	return n, rows.Err()
}
