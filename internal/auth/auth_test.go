package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/api/idtoken"
)

const aud = "test-web-client-id"

func payload(mod func(p *idtoken.Payload)) *idtoken.Payload {
	p := &idtoken.Payload{
		Issuer: "https://accounts.google.com", Audience: aud, Subject: "1234",
		Expires: time.Now().Add(time.Hour).Unix(),
		Claims:  map[string]any{"email": "a@example.com", "email_verified": true, "name": "A"},
	}
	if mod != nil {
		mod(p)
	}
	return p
}

func TestCheckClaims(t *testing.T) {
	now := time.Now()
	id, err := CheckClaims(payload(nil), aud, now)
	if err != nil || id.Subject != "1234" || id.Email != "a@example.com" || id.Name != "A" {
		t.Fatalf("valid payload: %+v %v", id, err)
	}
	if _, err := CheckClaims(payload(func(p *idtoken.Payload) { p.Issuer = "accounts.google.com" }), aud, now); err != nil {
		t.Fatalf("bare issuer should pass: %v", err)
	}
	if _, err := CheckClaims(payload(func(p *idtoken.Payload) { p.Claims["email_verified"] = "true" }), aud, now); err != nil {
		t.Fatalf("string email_verified should pass: %v", err)
	}
	bad := map[string]func(p *idtoken.Payload){
		"wrong aud":        func(p *idtoken.Payload) { p.Audience = "other-client" },
		"wrong iss":        func(p *idtoken.Payload) { p.Issuer = "https://evil.example" },
		"expired":          func(p *idtoken.Payload) { p.Expires = now.Add(-time.Second).Unix() },
		"unverified email": func(p *idtoken.Payload) { p.Claims["email_verified"] = false },
		"missing verified": func(p *idtoken.Payload) { delete(p.Claims, "email_verified") },
		"no email":         func(p *idtoken.Payload) { delete(p.Claims, "email") },
		"no sub":           func(p *idtoken.Payload) { p.Subject = "" },
	}
	for name, mod := range bad {
		if _, err := CheckClaims(payload(mod), aud, now); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("%s: expected ErrInvalidToken, got %v", name, err)
		}
	}
	if _, err := CheckClaims(payload(nil), "", now); err == nil {
		t.Error("empty client id must fail")
	}
}

func TestGoogleVerifierUsesValidatorAndClaims(t *testing.T) {
	g := NewGoogleVerifier(aud)
	g.validate = func(_ context.Context, tok, a string) (*idtoken.Payload, error) {
		if a != aud {
			t.Fatalf("audience not passed: %q", a)
		}
		if tok == "bad-sig" {
			return nil, errors.New("signature")
		}
		return payload(func(p *idtoken.Payload) { p.Audience = tok }), nil
	}
	if _, err := g.Verify(context.Background(), aud); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Verify(context.Background(), "wrong-aud"); err == nil {
		t.Fatal("wrong aud accepted")
	}
	if _, err := g.Verify(context.Background(), "bad-sig"); err == nil {
		t.Fatal("bad signature accepted")
	}
	if _, err := NewGoogleVerifier("").Verify(context.Background(), "x"); err == nil {
		t.Fatal("empty client id accepted")
	}
}

func TestTokensAndKeys(t *testing.T) {
	tok := NewToken()
	if len(tok) != 43 || tok == NewToken() {
		t.Fatalf("bad token %q", tok)
	}
	if Hash(tok) == tok || len(Hash(tok)) != 64 || !HashEqual(Hash(tok), Hash(tok)) || HashEqual(Hash(tok), Hash("x")) {
		t.Fatal("hash")
	}
	if err := ValidatePublicKey(RandomB64U(32)); err != nil {
		t.Fatal(err)
	}
	for _, pk := range []string{"", RandomB64U(31), RandomB64U(33), RandomB64U(32) + "=", strings.Repeat("+", 43), strings.Repeat("A", 42) + "B"} {
		if ValidatePublicKey(pk) == nil {
			t.Errorf("accepted %q", pk)
		}
	}
}
