package control

import (
	"database/sql"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestSharedSQLiteMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing.db")
	if e := os.WriteFile(path, nil, 0600); e != nil {
		t.Fatal(e)
	}
	// Create a genuine v1 database, then open through both management handles.
	raw, e := sql.Open("sqlite3", path)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = raw.Exec(schema); e != nil {
		t.Fatal(e)
	}
	raw.Close()
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, e := Open(path)
			if e != nil {
				errs <- e
				return
			}
			defer s.Close()
			var version int
			e = s.DB.QueryRow("PRAGMA user_version").Scan(&version)
			if e == nil && version != 5 {
				t.Errorf("schema version %d", version)
			}
			errs <- e
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
}
