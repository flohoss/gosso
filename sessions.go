package gosso

import (
	"context"
	"database/sql"
	"net/http"
	"time"
)

const (
	sessionTable = `CREATE TABLE IF NOT EXISTS sso_sessions (
		jti TEXT PRIMARY KEY,
		subject TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL
	)`

	sessionIndex = `CREATE INDEX IF NOT EXISTS idx_sso_sessions_expires_at ON sso_sessions (expires_at)`

	createSession = `INSERT INTO sso_sessions (jti, subject, created_at, expires_at) VALUES (?, ?, ?, ?)`

	activeSession = `SELECT subject FROM sso_sessions WHERE jti = ? AND expires_at > ?`

	deleteSession = `DELETE FROM sso_sessions WHERE jti = ?`

	deleteExpiredSessions = `DELETE FROM sso_sessions WHERE expires_at < ?`
)

// sessionTokenSize is the number of random bytes behind a session identifier.
const sessionTokenSize = 32

type sessionStore struct {
	db       *sql.DB
	cookie   string
	secure   bool
	tokenTTL time.Duration
}

func newSessionStore(opts Options) (*sessionStore, error) {
	if _, err := opts.DB.ExecContext(context.Background(), sessionTable); err != nil {
		return nil, err
	}
	if _, err := opts.DB.ExecContext(context.Background(), sessionIndex); err != nil {
		return nil, err
	}

	return &sessionStore{
		db:       opts.DB,
		cookie:   opts.CookieName,
		secure:   opts.CookieSecure,
		tokenTTL: opts.SessionTTL,
	}, nil
}

func (s *sessionStore) start(w http.ResponseWriter, r *http.Request, subject string) error {
	jti := RandomToken()

	expiresAt := time.Now().Add(s.tokenTTL)
	if _, err := s.db.ExecContext(r.Context(), createSession,
		jti, subject, time.Now().UnixMilli(), expiresAt.UnixMilli(),
	); err != nil {
		return err
	}

	http.SetCookie(w, newCookie(s.cookie, jti, 0, expiresAt, s.secure))

	return nil
}

func (s *sessionStore) authenticate(r *http.Request) (*User, error) {
	cookie, err := r.Cookie(s.cookie)
	if err != nil || cookie.Value == "" {
		return nil, ErrUnauthenticated
	}

	var subject string
	err = s.db.QueryRowContext(r.Context(), activeSession, cookie.Value, time.Now().UnixMilli()).Scan(&subject)
	if err != nil {
		return nil, ErrUnauthenticated
	}

	return &User{Subject: subject}, nil
}

func (s *sessionStore) clear(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(s.cookie)
	if err == nil && cookie.Value != "" {
		if _, err := s.db.ExecContext(r.Context(), deleteSession, cookie.Value); err != nil {
			logger.Load().Warn("Failed to revoke session", "error", err)
		}
	}

	http.SetCookie(w, newCookie(s.cookie, "", -1, time.Time{}, s.secure))
}

func (s *sessionStore) deleteExpired() {
	if _, err := s.db.ExecContext(context.Background(), deleteExpiredSessions, time.Now().UnixMilli()); err != nil {
		logger.Load().Warn("Failed to delete expired sessions", "error", err)
	}
}
