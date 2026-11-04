// Package apierr defines the relay's error codes (docs/protocol.md §4) and
// their HTTP statuses.
package apierr

import (
	"errors"
	"net/http"
)

// Error is an API error: an HTTP status plus a stable machine code.
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func newErr(status int, code string) func(msg string) *Error {
	return func(msg string) *Error { return &Error{Status: status, Code: code, Message: msg} }
}

// Constructors for every code in §4. `internal` is used for unexpected
// server failures only.
var (
	BadRequest     = newErr(http.StatusBadRequest, "bad_request")
	Unauthorized   = newErr(http.StatusUnauthorized, "unauthorized")
	Forbidden      = newErr(http.StatusForbidden, "forbidden")
	NotFound       = newErr(http.StatusNotFound, "not_found")
	Conflict       = newErr(http.StatusConflict, "conflict")
	Expired        = newErr(http.StatusGone, "expired")
	RateLimited    = newErr(http.StatusTooManyRequests, "rate_limited")
	DesktopOffline = newErr(http.StatusConflict, "desktop_offline")
	Internal       = newErr(http.StatusInternalServerError, "internal")
)

// From converts any error into an *Error; unknown errors become `internal`
// with a generic message so internals never leak to clients.
func From(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return Internal("internal error")
}
