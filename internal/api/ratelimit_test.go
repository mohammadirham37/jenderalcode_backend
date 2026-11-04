package api

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestLimiterBasics(t *testing.T) {
	now := time.Unix(1000, 0)
	l := NewLimiter(1, 3)
	l.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if !l.Allow("a") {
			t.Fatalf("burst request %d refused", i)
		}
	}
	if l.Allow("a") {
		t.Fatal("over burst allowed")
	}
	if !l.Allow("b") {
		t.Fatal("keys must be independent")
	}
	now = now.Add(1500 * time.Millisecond)
	if !l.Allow("a") || l.Allow("a") {
		t.Fatal("refill should give exactly one token after 1.5 s")
	}
	now = now.Add(time.Hour)
	for i := 0; i < 3; i++ {
		l.Allow("a")
	}
	if l.Allow("a") {
		t.Fatal("refill must cap at burst")
	}
	now = now.Add(time.Hour)
	l.Sweep()
	if len(l.buckets) != 0 {
		t.Fatalf("idle buckets not swept: %d", len(l.buckets))
	}
}

func TestClientIP(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:5555"
	r.Header.Set("X-Forwarded-For", "203.0.113.9, 198.51.100.7")
	if got := ClientIP(r, false); got != "127.0.0.1" {
		t.Fatalf("untrusted: %s", got)
	}
	if got := ClientIP(r, true); got != "198.51.100.7" {
		t.Fatalf("trusted: %s", got)
	}
	r.Header.Set("X-Forwarded-For", "garbage")
	if got := ClientIP(r, true); got != "127.0.0.1" {
		t.Fatalf("garbage xff: %s", got)
	}
}
