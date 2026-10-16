package gosso

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"
)

// ErrInvalidSession is returned for a session cookie that is malformed, tampered with or expired.
var ErrInvalidSession = errors.New("invalid session cookie")

const sessionFieldSeparator = "|"

// SignHMAC returns the base64url payload and HMAC-SHA256 signature for subject and expiresAt.
func SignHMAC(key, subject string, expiresAt time.Time) string {
	payload := subject + sessionFieldSeparator + strconv.FormatInt(expiresAt.Unix(), 10)

	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(payload))

	return base64.RawURLEncoding.EncodeToString([]byte(payload)) +
		"." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// VerifyHMAC validates the signature of value and returns the subject and expiry it carries.
func VerifyHMAC(key, value string, now time.Time) (string, time.Time, error) {
	encodedPayload, encodedMAC, found := strings.Cut(value, ".")
	if !found {
		return "", time.Time{}, ErrInvalidSession
	}

	payload, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return "", time.Time{}, ErrInvalidSession
	}

	providedMAC, err := base64.RawURLEncoding.DecodeString(encodedMAC)
	if err != nil {
		return "", time.Time{}, ErrInvalidSession
	}

	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(payload)
	if !hmac.Equal(providedMAC, mac.Sum(nil)) {
		return "", time.Time{}, ErrInvalidSession
	}

	subject, rawExpiry, found := strings.Cut(string(payload), sessionFieldSeparator)
	if !found || subject == "" {
		return "", time.Time{}, ErrInvalidSession
	}

	expiryUnix, err := strconv.ParseInt(rawExpiry, 10, 64)
	if err != nil {
		return "", time.Time{}, ErrInvalidSession
	}

	expiresAt := time.Unix(expiryUnix, 0)
	if !now.Before(expiresAt) {
		return "", time.Time{}, ErrInvalidSession
	}

	return subject, expiresAt, nil
}

// ValidateSessionKey reports ErrInvalidSessionKey when key is shorter than MinSessionKeyLength.
func ValidateSessionKey(key string) error {
	if len(key) < MinSessionKeyLength {
		return ErrInvalidSessionKey
	}

	return nil
}
