package gosso

import (
	"errors"
	"testing"
	"time"
)

func TestVerifyHMAC_AcceptsSignedSubject(t *testing.T) {
	expiresAt := time.Now().Add(time.Hour).Truncate(time.Second).Add(3 * time.Second)
	value := SignHMAC(testSessionKey, "user-subject", expiresAt)

	subject, verifiedExpiry, err := VerifyHMAC(testSessionKey, value, time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if subject != "user-subject" {
		t.Fatalf("expected the subject to round-trip, got %q", subject)
	}
	if !verifiedExpiry.Equal(expiresAt) {
		t.Fatalf("expected expiry %v, got %v", expiresAt, verifiedExpiry)
	}
}

func TestVerifyHMAC_RejectsTamperedPayload(t *testing.T) {
	value := SignHMAC(testSessionKey, "user-subject", time.Now().Add(time.Hour))

	forged := value[:len(value)-20] + "00000000000000000000"
	if _, _, err := VerifyHMAC(testSessionKey, forged, time.Now()); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("expected ErrInvalidSession for a tampered payload, got %v", err)
	}
}

func TestVerifyHMAC_RejectsSignedByAnotherKey(t *testing.T) {
	value := SignHMAC(testSessionKey, "user-subject", time.Now().Add(time.Hour))

	if _, _, err := VerifyHMAC("another-sufficiently-long-key-xxxxxxxxx", value, time.Now()); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("expected ErrInvalidSession for another key, got %v", err)
	}
}

func TestVerifyHMAC_RejectsExpiredSession(t *testing.T) {
	value := SignHMAC(testSessionKey, "user-subject", time.Now().Add(-time.Minute))

	if _, _, err := VerifyHMAC(testSessionKey, value, time.Now()); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("expected ErrInvalidSession for an expired session, got %v", err)
	}
}

func TestVerifyHMAC_RejectsMissingSeparator(t *testing.T) {
	if _, _, err := VerifyHMAC(testSessionKey, "nonsense", time.Now()); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("expected ErrInvalidSession, got %v", err)
	}
}

func TestVerifyHMAC_RejectsEmptySubject(t *testing.T) {
	value := SignHMAC(testSessionKey, "", time.Now().Add(time.Hour))

	if _, _, err := VerifyHMAC(testSessionKey, value, time.Now()); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("expected ErrInvalidSession for an empty subject, got %v", err)
	}
}
