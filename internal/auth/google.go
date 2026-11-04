package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/api/idtoken"
)

// Identity is the verified identity behind an ID token.
type Identity struct {
	Subject, Email, Name string
}

// IDTokenVerifier verifies a Google ID token.
type IDTokenVerifier interface {
	Verify(ctx context.Context, idToken string) (Identity, error)
}

// ErrInvalidToken is returned for any token that fails verification.
var ErrInvalidToken = errors.New("invalid id token")

var googleIssuers = map[string]bool{"accounts.google.com": true, "https://accounts.google.com": true}

// GoogleVerifier verifies signatures with Google's published keys via
// idtoken and then checks iss, aud, exp and email_verified itself.
type GoogleVerifier struct {
	ClientID string // the Google *web* client ID
	validate func(ctx context.Context, token, aud string) (*idtoken.Payload, error)
	now      func() time.Time
}

func NewGoogleVerifier(clientID string) *GoogleVerifier {
	return &GoogleVerifier{ClientID: clientID, validate: idtoken.Validate, now: time.Now}
}

func (g *GoogleVerifier) Verify(ctx context.Context, token string) (Identity, error) {
	if g.ClientID == "" {
		// idtoken skips the audience check for an empty audience.
		return Identity{}, errors.New("google client id not configured")
	}
	p, err := g.validate(ctx, token, g.ClientID)
	if err != nil {
		return Identity{}, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	return CheckClaims(p, g.ClientID, g.now())
}

// CheckClaims validates the claims of an (already signature-checked) payload.
func CheckClaims(p *idtoken.Payload, clientID string, now time.Time) (Identity, error) {
	if p == nil || clientID == "" {
		return Identity{}, ErrInvalidToken
	}
	if !googleIssuers[p.Issuer] {
		return Identity{}, fmt.Errorf("%w: bad iss", ErrInvalidToken)
	}
	if p.Audience != clientID {
		return Identity{}, fmt.Errorf("%w: bad aud", ErrInvalidToken)
	}
	if now.Unix() >= p.Expires {
		return Identity{}, fmt.Errorf("%w: expired", ErrInvalidToken)
	}
	if p.Subject == "" {
		return Identity{}, fmt.Errorf("%w: no sub", ErrInvalidToken)
	}
	email, _ := p.Claims["email"].(string)
	if email == "" {
		return Identity{}, fmt.Errorf("%w: no email", ErrInvalidToken)
	}
	verified := false
	switch v := p.Claims["email_verified"].(type) {
	case bool:
		verified = v
	case string:
		verified = v == "true"
	}
	if !verified {
		return Identity{}, fmt.Errorf("%w: email not verified", ErrInvalidToken)
	}
	name, _ := p.Claims["name"].(string)
	return Identity{Subject: p.Subject, Email: email, Name: name}, nil
}

// FakeVerifier maps raw tokens to identities; for tests only.
type FakeVerifier map[string]Identity

func (f FakeVerifier) Verify(_ context.Context, token string) (Identity, error) {
	id, ok := f[token]
	if !ok {
		return Identity{}, ErrInvalidToken
	}
	return id, nil
}
