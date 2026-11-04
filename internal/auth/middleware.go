package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/mohammadirham37/jenderalcode_backend/internal/store"
)

type ctxKey struct{}

// DeviceLookup loads a non-revoked device by token hash.
type DeviceLookup interface {
	DeviceByTokenHash(ctx context.Context, hash string) (store.Device, error)
}

// ErrNoToken means the request carried no Authorization header.
var ErrNoToken = errors.New("no bearer token")

// BearerToken extracts the token from "Authorization: Bearer <token>".
func BearerToken(r *http.Request) (string, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", ErrNoToken
	}
	scheme, tok, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || tok == "" || len(tok) > 256 {
		return "", errors.New("malformed authorization header")
	}
	return tok, nil
}

// Authenticate resolves a raw token to its non-revoked device.
func Authenticate(ctx context.Context, l DeviceLookup, token string) (store.Device, error) {
	if token == "" || len(token) > 256 {
		return store.Device{}, store.ErrNotFound
	}
	h := Hash(token)
	d, err := l.DeviceByTokenHash(ctx, h)
	if err != nil {
		return d, err
	}
	return d, nil
}

// Middleware requires (or, when optional, permits the absence of) a valid
// device token. A present but invalid token is always rejected. fail writes
// the error response (and receives the lookup error for logging decisions).
func Middleware(l DeviceLookup, optional bool, fail func(w http.ResponseWriter, err error)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tok, err := BearerToken(r)
			if errors.Is(err, ErrNoToken) && optional {
				next.ServeHTTP(w, r)
				return
			}
			if err != nil {
				fail(w, err)
				return
			}
			d, err := Authenticate(r.Context(), l, tok)
			if err != nil {
				fail(w, err)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, d)))
		})
	}
}

// DeviceFrom returns the authenticated device, if any.
func DeviceFrom(ctx context.Context) (store.Device, bool) {
	d, ok := ctx.Value(ctxKey{}).(store.Device)
	return d, ok
}
