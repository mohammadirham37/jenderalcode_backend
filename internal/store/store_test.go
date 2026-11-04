package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestMigrationsIdempotentAndPragmas(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n)
	if n != 1 {
		t.Fatalf("migrations recorded: %d", n)
	}
	var fk int
	var mode string
	s.db.QueryRow(`PRAGMA foreign_keys`).Scan(&fk)
	s.db.QueryRow(`PRAGMA journal_mode`).Scan(&mode)
	if fk != 1 || mode != "wal" {
		t.Fatalf("foreign_keys=%d journal_mode=%s", fk, mode)
	}
}

func TestRevokeDeletesPairsAndToken(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	u, _ := s.UpsertUser(ctx, "sub", "a@example.com", "A", 1)
	u2, _ := s.UpsertUser(ctx, "sub", "b@example.com", "B", 2)
	if u.ID != u2.ID {
		t.Fatal("upsert created a second user")
	}
	m, _, err := s.LoginMobile(ctx, u.ID, "phone", "pk-m", "hash-m", 1)
	if err != nil {
		t.Fatal(err)
	}
	mobile, _ := s.DeviceByID(ctx, m)
	p := Pairing{ID: "p1", CodeHash: "c", WaitSecretHash: "w", DesktopPublicKey: "pk-d", DesktopName: "L", ExpiresAt: 100}
	if err := s.CreatePairing(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := s.ClaimPairing(ctx, "p1", m, 10); err != nil {
		t.Fatal(err)
	}
	d, created, err := s.ApprovePairing(ctx, ApproveParams{PairingID: "p1", Mobile: mobile, NewDesktopID: "d1", DesktopTokenHash: "hash-d", Now: 20})
	if err != nil || !created || d != "d1" {
		t.Fatal(d, created, err)
	}
	if _, _, err := s.ApprovePairing(ctx, ApproveParams{PairingID: "p1", Mobile: mobile, NewDesktopID: "d2", DesktopTokenHash: "h2", Now: 21}); err != ErrConflict {
		t.Fatalf("second approve: %v", err)
	}
	if ok, _ := s.IsPaired(ctx, m, "d1"); !ok {
		t.Fatal("not paired")
	}
	peers, err := s.RevokeDevice(ctx, "d1", 30)
	if err != nil || len(peers) != 1 || peers[0] != m {
		t.Fatal(peers, err)
	}
	if _, err := s.DeviceByTokenHash(ctx, "hash-d"); err != ErrNotFound {
		t.Fatalf("revoked token still resolves: %v", err)
	}
	if ok, _ := s.IsPaired(ctx, m, "d1"); ok {
		t.Fatal("still paired")
	}
	if peers, _ := s.RevokeDevice(ctx, "d1", 31); len(peers) != 0 {
		t.Fatal("double revoke returned peers")
	}
}
