package gosso

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestNewSessionStore_CreatesTheStore(t *testing.T) {
	opts := testOptions()
	opts.DB = newTestDB(t)

	store, err := newSessionStore(opts)
	if store == nil || err != nil {
		t.Fatalf("expected a store backed by a writable database, got %v", err)
	}
}

func TestSessionStore_StartReportsInsertFailures(t *testing.T) {
	auth := newTestAuth(t)
	auth.sessions.db.Close()

	rec, req := newTestContext(http.MethodGet, "/")
	if err := auth.sessions.start(rec, req, "user-subject"); err == nil {
		t.Fatal("expected an error when the insert fails")
	}
}

func TestSessionStore_ClearSurvivesDatabaseFailures(t *testing.T) {
	auth := newTestAuth(t)
	cookie := startTestSession(t, auth, "user-subject")
	auth.sessions.db.Close()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	auth.sessions.clear(rec, req)

	expired := sessionCookieOf(t, rec.Result().Cookies(), auth)
	if expired == nil || expired.MaxAge != -1 {
		t.Fatal("expected the session cookie to be expired regardless of the database failure")
	}
}

func TestSessionStore_DeleteExpiredReportsErrors(t *testing.T) {
	auth := newTestAuth(t)

	if count := sessionCount(t, auth); count != 0 {
		t.Fatalf("expected an empty store, got %d sessions", count)
	}

	auth.sessions.db.Close()
	auth.sessions.deleteExpired()
}

func TestNewSessionStore_ReportsDatabaseFailures(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "sso.sqlite"))
	if err != nil {
		t.Fatalf("failed to open the database: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	opts := testOptions()
	opts.DB = db
	opts.SessionTTL = DefaultSessionTTL

	// A closed database cannot create the session table or its index.
	store, creationErr := func() (*sessionStore, error) {
		db.Close()
		return newSessionStore(opts)
	}()
	if creationErr == nil {
		t.Fatal("expected an error when the session table cannot be created")
	}

	if store == nil {
		t.Log("newSessionStore returned no store alongside the error")
	}
}
