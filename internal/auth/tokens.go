// Package auth: Google ID token verification, device tokens (stored only as
// SHA-256 hashes) and the Bearer middleware.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
)

var b64u = base64.RawURLEncoding

// RandomB64U returns b64u(n random bytes).
func RandomB64U(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return b64u.EncodeToString(b)
}

// NewToken returns a device token: b64u(32 random bytes).
func NewToken() string { return RandomB64U(32) }

// Hash returns hex(SHA-256(s)), the only form in which tokens, wait secrets
// and pairing codes are stored.
func Hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// HashEqual compares two hashes in constant time.
func HashEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ValidatePublicKey checks that pk is base64url without padding and decodes
// to exactly 32 bytes (an X25519 public key).
func ValidatePublicKey(pk string) error {
	if len(pk) != 43 || strings.ContainsAny(pk, "=+/") {
		return errors.New("public_key must be 43 chars of unpadded base64url")
	}
	raw, err := b64u.Strict().DecodeString(pk)
	if err != nil || len(raw) != 32 {
		return errors.New("public_key must decode to 32 bytes")
	}
	return nil
}
