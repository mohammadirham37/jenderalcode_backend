// Package store is the relay's SQLite persistence (pure Go driver). It holds
// users, devices (tokens only as SHA-256 hashes), pairs and pending pairings.
// It never stores message bodies.
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Sentinel errors; callers map them to API codes.
var (
	ErrNotFound  = errors.New("not found")
	ErrConflict  = errors.New("conflict")
	ErrExpired   = errors.New("expired")
	ErrForbidden = errors.New("forbidden")
)

const (
	KindDesktop = "desktop"
	KindMobile  = "mobile"
)

type Store struct{ db *sql.DB }

type User struct {
	ID, GoogleSub, Email, Name string
	CreatedAt                  int64
}

type Device struct {
	ID, UserID, Kind, Name, PublicKey string
	CreatedAt                         int64
	LastSeen                          *int64
	RevokedAt                         *int64
}

type Pairing struct {
	ID, CodeHash, WaitSecretHash  string
	DesktopPublicKey, DesktopName string
	ExistingDesktopID, ClaimedBy  *string
	ExpiresAt                     int64
	ConsumedAt                    *int64
}

// Open opens (creating if needed) the database at path and applies migrations.
func Open(path string) (*Store, error) {
	q := url.Values{}
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "synchronous(NORMAL)")
	q.Set("_txlock", "immediate")
	db, err := sql.Open("sqlite", "file:"+path+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)
	db.SetConnMaxIdleTime(5 * time.Minute)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL)`); err != nil {
		return err
	}
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return err
	}
	type mig struct {
		version int
		name    string
	}
	var migs []mig
	for _, e := range entries {
		prefix, _, ok := strings.Cut(e.Name(), "_")
		v, err := strconv.Atoi(prefix)
		if !ok || err != nil || !strings.HasSuffix(e.Name(), ".sql") {
			return fmt.Errorf("bad migration file name %q", e.Name())
		}
		migs = append(migs, mig{v, e.Name()})
	}
	sort.Slice(migs, func(i, j int) bool { return migs[i].version < migs[j].version })
	for _, m := range migs {
		body, err := migrationFS.ReadFile("migrations/" + m.name)
		if err != nil {
			return err
		}
		err = s.tx(ctx, func(tx *sql.Tx) error {
			var n int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, m.version).Scan(&n); err != nil {
				return err
			}
			if n > 0 {
				return nil
			}
			if _, err := tx.ExecContext(ctx, string(body)); err != nil {
				return fmt.Errorf("%s: %w", m.name, err)
			}
			_, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, name, applied_at) VALUES (?, ?, ?)`,
				m.version, m.name, time.Now().UnixMilli())
			return err
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) tx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// UpsertUser finds the user by Google subject (creating it if new) and
// refreshes email and name.
func (s *Store) UpsertUser(ctx context.Context, sub, email, name string, now int64) (User, error) {
	u := User{ID: uuid.NewString(), GoogleSub: sub, Email: email, Name: name, CreatedAt: now}
	err := s.db.QueryRowContext(ctx, `INSERT INTO users(id, google_sub, email, name, created_at) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(google_sub) DO UPDATE SET email = excluded.email, name = excluded.name
		RETURNING id, created_at`, u.ID, sub, email, name, now).Scan(&u.ID, &u.CreatedAt)
	return u, err
}

func (s *Store) UserByID(ctx context.Context, id string) (User, error) {
	var u User
	err := s.db.QueryRowContext(ctx, `SELECT id, google_sub, email, name, created_at FROM users WHERE id = ?`, id).
		Scan(&u.ID, &u.GoogleSub, &u.Email, &u.Name, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return u, ErrNotFound
	}
	return u, err
}

// LoginMobile registers a mobile device for the user, or, when a non-revoked
// mobile device of that user already has publicKey, reuses its id and
// rotates its token (§4). Returns the device id and whether it was reused.
func (s *Store) LoginMobile(ctx context.Context, userID, name, publicKey, tokenHash string, now int64) (string, bool, error) {
	var id string
	reused := false
	err := s.tx(ctx, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, `SELECT id FROM devices WHERE user_id = ? AND kind = 'mobile'
			AND public_key = ? AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1`, userID, publicKey).Scan(&id)
		switch {
		case err == nil:
			reused = true
			_, err = tx.ExecContext(ctx, `UPDATE devices SET token_hash = ?, name = ? WHERE id = ?`, tokenHash, name, id)
			return err
		case errors.Is(err, sql.ErrNoRows):
			id = uuid.NewString()
			_, err = tx.ExecContext(ctx, `INSERT INTO devices(id, user_id, kind, name, public_key, token_hash, created_at)
				VALUES (?, ?, 'mobile', ?, ?, ?, ?)`, id, userID, name, publicKey, tokenHash, now)
			return err
		default:
			return err
		}
	})
	return id, reused, err
}

const deviceCols = `id, user_id, kind, name, public_key, created_at, last_seen, revoked_at`

func scanDevice(row interface{ Scan(...any) error }) (Device, error) {
	var d Device
	var last, rev sql.NullInt64
	err := row.Scan(&d.ID, &d.UserID, &d.Kind, &d.Name, &d.PublicKey, &d.CreatedAt, &last, &rev)
	if errors.Is(err, sql.ErrNoRows) {
		return d, ErrNotFound
	}
	if last.Valid {
		d.LastSeen = &last.Int64
	}
	if rev.Valid {
		d.RevokedAt = &rev.Int64
	}
	return d, err
}

// DeviceByTokenHash returns the non-revoked device owning the token hash.
func (s *Store) DeviceByTokenHash(ctx context.Context, hash string) (Device, error) {
	return scanDevice(s.db.QueryRowContext(ctx, `SELECT `+deviceCols+` FROM devices
		WHERE token_hash = ? AND revoked_at IS NULL`, hash))
}

// DeviceByID returns the device, revoked or not.
func (s *Store) DeviceByID(ctx context.Context, id string) (Device, error) {
	return scanDevice(s.db.QueryRowContext(ctx, `SELECT `+deviceCols+` FROM devices WHERE id = ?`, id))
}

func (s *Store) TouchLastSeen(ctx context.Context, id string, now int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE devices SET last_seen = ? WHERE id = ?`, now, id)
	return err
}

// Peers lists the non-revoked devices paired with deviceID.
func (s *Store) Peers(ctx context.Context, deviceID string) ([]Device, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+prefixed("d.", deviceCols)+` FROM pairs p
		JOIN devices d ON d.id = CASE WHEN p.desktop_id = ? THEN p.mobile_id ELSE p.desktop_id END
		WHERE (p.desktop_id = ? OR p.mobile_id = ?) AND d.revoked_at IS NULL
		ORDER BY p.created_at, d.id`, deviceID, deviceID, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func prefixed(p, cols string) string {
	parts := strings.Split(cols, ", ")
	for i := range parts {
		parts[i] = p + parts[i]
	}
	return strings.Join(parts, ", ")
}

// IsPaired reports whether a and b form a pair and neither is revoked.
func (s *Store) IsPaired(ctx context.Context, a, b string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pairs p
		JOIN devices d1 ON d1.id = p.desktop_id JOIN devices d2 ON d2.id = p.mobile_id
		WHERE ((p.desktop_id = ? AND p.mobile_id = ?) OR (p.desktop_id = ? AND p.mobile_id = ?))
		AND d1.revoked_at IS NULL AND d2.revoked_at IS NULL`, a, b, b, a).Scan(&n)
	return n > 0, err
}

// DeletePair removes the pair between a and b (either orientation).
// Returns ErrNotFound when there is none.
func (s *Store) DeletePair(ctx context.Context, a, b string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM pairs WHERE (desktop_id = ? AND mobile_id = ?)
		OR (desktop_id = ? AND mobile_id = ?)`, a, b, b, a)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// RevokeDevice marks the device revoked, invalidates its token hash, deletes
// all its pairs and returns the former peers. Revoking twice is a no-op that
// returns no peers.
func (s *Store) RevokeDevice(ctx context.Context, id string, now int64) ([]string, error) {
	var peers []string
	err := s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE devices SET revoked_at = ?, token_hash = 'revoked:' || id
			WHERE id = ? AND revoked_at IS NULL`, now, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return nil
		}
		rows, err := tx.QueryContext(ctx, `SELECT CASE WHEN desktop_id = ? THEN mobile_id ELSE desktop_id END
			FROM pairs WHERE desktop_id = ? OR mobile_id = ?`, id, id, id)
		if err != nil {
			return err
		}
		for rows.Next() {
			var p string
			if err := rows.Scan(&p); err != nil {
				rows.Close()
				return err
			}
			peers = append(peers, p)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM pairs WHERE desktop_id = ? OR mobile_id = ?`, id, id); err != nil {
			return err
		}
		// Pending pairings that would add a phone to this desktop, or were
		// claimed by this phone, must not be usable any more.
		_, err = tx.ExecContext(ctx, `DELETE FROM pairings WHERE existing_desktop_id = ? OR claimed_by = ?`, id, id)
		return err
	})
	return peers, err
}

const pairingCols = `id, code_hash, wait_secret_hash, desktop_public_key, desktop_name, existing_desktop_id, claimed_by, expires_at, consumed_at`

func scanPairing(row interface{ Scan(...any) error }) (Pairing, error) {
	var p Pairing
	var existing, claimed sql.NullString
	var consumed sql.NullInt64
	err := row.Scan(&p.ID, &p.CodeHash, &p.WaitSecretHash, &p.DesktopPublicKey, &p.DesktopName,
		&existing, &claimed, &p.ExpiresAt, &consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	if existing.Valid {
		p.ExistingDesktopID = &existing.String
	}
	if claimed.Valid {
		p.ClaimedBy = &claimed.String
	}
	if consumed.Valid {
		p.ConsumedAt = &consumed.Int64
	}
	return p, err
}

func (s *Store) CreatePairing(ctx context.Context, p Pairing) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO pairings(`+pairingCols+`) VALUES (?, ?, ?, ?, ?, ?, NULL, ?, NULL)`,
		p.ID, p.CodeHash, p.WaitSecretHash, p.DesktopPublicKey, p.DesktopName, p.ExistingDesktopID, p.ExpiresAt)
	return err
}

func (s *Store) PairingByID(ctx context.Context, id string) (Pairing, error) {
	return scanPairing(s.db.QueryRowContext(ctx, `SELECT `+pairingCols+` FROM pairings WHERE id = ?`, id))
}

func (s *Store) PairingByCodeHash(ctx context.Context, hash string) (Pairing, error) {
	return scanPairing(s.db.QueryRowContext(ctx, `SELECT `+pairingCols+` FROM pairings WHERE code_hash = ?`, hash))
}

// ClaimPairing marks the pairing as claimed by mobileID. It succeeds again
// for the same phone and fails with ErrConflict for any other phone, or when
// the pairing was consumed, and ErrExpired once it has expired.
func (s *Store) ClaimPairing(ctx context.Context, id, mobileID string, now int64) error {
	res, err := s.db.ExecContext(ctx, `UPDATE pairings SET claimed_by = ?
		WHERE id = ? AND (claimed_by IS NULL OR claimed_by = ?) AND consumed_at IS NULL AND expires_at > ?`,
		mobileID, id, mobileID, now)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 1 {
		return nil
	}
	p, err := s.PairingByID(ctx, id)
	if err != nil {
		return err
	}
	if p.ExpiresAt <= now {
		return ErrExpired
	}
	return ErrConflict
}

// ApproveParams describes a pairing approval.
type ApproveParams struct {
	PairingID string
	Mobile    Device
	// NewDesktopID and DesktopTokenHash are used only when the pairing has
	// no existing desktop.
	NewDesktopID     string
	DesktopTokenHash string
	Now              int64
}

// ApprovePairing atomically re-checks the pairing (claimed by this phone,
// not consumed, not expired), creates the desktop device if the pairing is
// for a new desktop, creates the pair and consumes the pairing. It returns
// the desktop id and whether the desktop was created.
func (s *Store) ApprovePairing(ctx context.Context, a ApproveParams) (string, bool, error) {
	var desktopID string
	created := false
	err := s.tx(ctx, func(tx *sql.Tx) error {
		p, err := scanPairing(tx.QueryRowContext(ctx, `SELECT `+pairingCols+` FROM pairings WHERE id = ?`, a.PairingID))
		if err != nil {
			return err
		}
		switch {
		case p.ClaimedBy == nil || *p.ClaimedBy != a.Mobile.ID:
			return ErrForbidden
		case p.ConsumedAt != nil:
			return ErrConflict
		case p.ExpiresAt <= a.Now:
			return ErrExpired
		}
		if p.ExistingDesktopID != nil {
			d, err := scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceCols+` FROM devices WHERE id = ?`, *p.ExistingDesktopID))
			if err != nil {
				return err
			}
			if d.RevokedAt != nil || d.UserID != a.Mobile.UserID || d.Kind != KindDesktop {
				return ErrForbidden
			}
			desktopID = d.ID
		} else {
			desktopID = a.NewDesktopID
			created = true
			if _, err := tx.ExecContext(ctx, `INSERT INTO devices(id, user_id, kind, name, public_key, token_hash, created_at)
				VALUES (?, ?, 'desktop', ?, ?, ?, ?)`, desktopID, a.Mobile.UserID, p.DesktopName, p.DesktopPublicKey,
				a.DesktopTokenHash, a.Now); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO pairs(desktop_id, mobile_id, created_at) VALUES (?, ?, ?)
			ON CONFLICT DO NOTHING`, desktopID, a.Mobile.ID, a.Now); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE pairings SET consumed_at = ? WHERE id = ?`, a.Now, a.PairingID)
		return err
	})
	return desktopID, created, err
}

// UndoApproval reverts ApprovePairing when the desktop could not be told:
// it removes the pair and, for a newly created desktop, the device itself.
func (s *Store) UndoApproval(ctx context.Context, desktopID, mobileID string, deleteDesktop bool) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM pairs WHERE desktop_id = ? AND mobile_id = ?`, desktopID, mobileID); err != nil {
			return err
		}
		if deleteDesktop {
			_, err := tx.ExecContext(ctx, `DELETE FROM devices WHERE id = ? AND kind = 'desktop'`, desktopID)
			return err
		}
		return nil
	})
}

// DeleteExpiredPairings removes pairings that expired before now.
func (s *Store) DeleteExpiredPairings(ctx context.Context, now int64) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM pairings WHERE expires_at <= ?`, now)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
