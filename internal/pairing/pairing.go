// Package pairing implements desktop/mobile pairing (docs/protocol.md §4,
// §5.2): create, wait (WebSocket), claim and approve.
package pairing

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"github.com/mohammadirham37/jenderalcode_backend/internal/apierr"
	"github.com/mohammadirham37/jenderalcode_backend/internal/auth"
	"github.com/mohammadirham37/jenderalcode_backend/internal/hub"
	"github.com/mohammadirham37/jenderalcode_backend/internal/store"
)

const (
	// TTL is how long a pairing code is valid (§4).
	TTL = 120 * time.Second
	// MaxNameRunes caps device and desktop names.
	MaxNameRunes = 64

	deliverTimeout = 10 * time.Second
)

// Service owns pending pairings and the desktops waiting on them.
type Service struct {
	store *store.Store
	hub   *hub.Hub
	log   *slog.Logger

	TTL          time.Duration // tests may shorten it
	AuthTimeout  time.Duration
	PingInterval time.Duration
	ReadDeadline time.Duration

	mu      sync.Mutex
	waiters map[string]*waiter
	wg      sync.WaitGroup // live ServeWait handlers
}

func New(st *store.Store, h *hub.Hub, log *slog.Logger) *Service {
	return &Service{
		store: st, hub: h, log: log,
		TTL: TTL, AuthTimeout: hub.AuthTimeout, PingInterval: hub.PingInterval, ReadDeadline: hub.ReadDeadline,
		waiters: map[string]*waiter{},
	}
}

// CreateResult is the POST /v1/pairings response.
type CreateResult struct {
	PairingID  string `json:"pairing_id"`
	WaitSecret string `json:"wait_secret"`
	Code       string `json:"code"`
	ExpiresAt  int64  `json:"expires_at"`
}

// Create starts a pairing. existing is the authenticated desktop when the
// request carried a desktop token (adding a phone to that desktop).
func (s *Service) Create(ctx context.Context, publicKey, name string, existing *store.Device) (CreateResult, error) {
	if err := auth.ValidatePublicKey(publicKey); err != nil {
		return CreateResult{}, apierr.BadRequest(err.Error())
	}
	name, err := CleanName(name, "name")
	if err != nil {
		return CreateResult{}, err
	}
	var existingID *string
	if existing != nil {
		if existing.Kind != store.KindDesktop {
			return CreateResult{}, apierr.Forbidden("only a desktop token may create a pairing")
		}
		if existing.PublicKey != publicKey {
			return CreateResult{}, apierr.BadRequest("public_key does not match the registered desktop")
		}
		existingID = &existing.ID
	}
	res := CreateResult{
		PairingID:  uuid.NewString(),
		WaitSecret: auth.RandomB64U(32),
		Code:       auth.RandomB64U(16),
		ExpiresAt:  time.Now().Add(s.TTL).UnixMilli(),
	}
	err = s.store.CreatePairing(ctx, store.Pairing{
		ID: res.PairingID, CodeHash: auth.Hash(res.Code), WaitSecretHash: auth.Hash(res.WaitSecret),
		DesktopPublicKey: publicKey, DesktopName: name, ExistingDesktopID: existingID, ExpiresAt: res.ExpiresAt,
	})
	if err != nil {
		return CreateResult{}, err
	}
	s.log.Info("pairing created", "pairing_id", res.PairingID, "existing_desktop", existingID != nil)
	return res, nil
}

// ClaimResult is the POST /v1/pairings/claim response.
type ClaimResult struct {
	PairingID        string `json:"pairing_id"`
	DesktopName      string `json:"desktop_name"`
	DesktopPublicKey string `json:"desktop_public_key"`
	ExpiresAt        int64  `json:"expires_at"`
}

// Claim binds the pairing to the calling phone.
func (s *Service) Claim(ctx context.Context, mobile store.Device, code string) (ClaimResult, error) {
	if mobile.Kind != store.KindMobile {
		return ClaimResult{}, apierr.Forbidden("only a mobile device may claim a pairing")
	}
	if code == "" || len(code) > 64 {
		return ClaimResult{}, apierr.BadRequest("code is required")
	}
	p, err := s.store.PairingByCodeHash(ctx, auth.Hash(code))
	if errors.Is(err, store.ErrNotFound) {
		return ClaimResult{}, apierr.NotFound("unknown pairing code")
	}
	if err != nil {
		return ClaimResult{}, err
	}
	now := time.Now().UnixMilli()
	if p.ExpiresAt <= now {
		return ClaimResult{}, apierr.Expired("pairing code expired")
	}
	if err := s.checkExistingDesktop(ctx, p, mobile); err != nil {
		return ClaimResult{}, err
	}
	if err := s.store.ClaimPairing(ctx, p.ID, mobile.ID, now); err != nil {
		return ClaimResult{}, mapStoreErr(err)
	}
	s.log.Info("pairing claimed", "pairing_id", p.ID, "mobile_id", mobile.ID)
	return ClaimResult{PairingID: p.ID, DesktopName: p.DesktopName, DesktopPublicKey: p.DesktopPublicKey, ExpiresAt: p.ExpiresAt}, nil
}

func (s *Service) checkExistingDesktop(ctx context.Context, p store.Pairing, mobile store.Device) error {
	if p.ExistingDesktopID == nil {
		return nil
	}
	d, err := s.store.DeviceByID(ctx, *p.ExistingDesktopID)
	if errors.Is(err, store.ErrNotFound) {
		return apierr.NotFound("unknown pairing code")
	}
	if err != nil {
		return err
	}
	if d.RevokedAt != nil || d.UserID != mobile.UserID {
		return apierr.Forbidden("this desktop belongs to another account")
	}
	return nil
}

type approvedFrame struct {
	T               string  `json:"t"`
	DeviceID        string  `json:"device_id"`
	DeviceToken     *string `json:"device_token"`
	MobileDeviceID  string  `json:"mobile_device_id"`
	MobileName      string  `json:"mobile_name"`
	MobilePublicKey string  `json:"mobile_public_key"`
	UserEmail       string  `json:"user_email"`
}

// Approve completes the pairing for the phone that claimed it and hands the
// result to the waiting desktop. Returns the desktop device id.
func (s *Service) Approve(ctx context.Context, mobile store.Device, pairingID string) (string, error) {
	if mobile.Kind != store.KindMobile {
		return "", apierr.Forbidden("only a mobile device may approve a pairing")
	}
	p, err := s.store.PairingByID(ctx, pairingID)
	if errors.Is(err, store.ErrNotFound) {
		return "", apierr.NotFound("unknown pairing")
	}
	if err != nil {
		return "", err
	}
	now := time.Now().UnixMilli()
	switch {
	case p.ClaimedBy == nil || *p.ClaimedBy != mobile.ID:
		return "", apierr.Forbidden("pairing was not claimed by this device")
	case p.ConsumedAt != nil:
		return "", apierr.Conflict("pairing already used")
	case p.ExpiresAt <= now:
		return "", apierr.Expired("pairing expired")
	}
	if err := s.checkExistingDesktop(ctx, p, mobile); err != nil {
		return "", err
	}
	user, err := s.store.UserByID(ctx, mobile.UserID)
	if err != nil {
		return "", err
	}

	w := s.take(pairingID)
	if w == nil {
		return "", apierr.DesktopOffline("the desktop is not waiting for this pairing")
	}
	var token *string
	var tokenHash string
	if p.ExistingDesktopID == nil {
		t := auth.NewToken()
		token, tokenHash = &t, auth.Hash(t)
	}
	desktopID, created, err := s.store.ApprovePairing(ctx, store.ApproveParams{
		PairingID: pairingID, Mobile: mobile, NewDesktopID: uuid.NewString(), DesktopTokenHash: tokenHash, Now: now,
	})
	if err != nil {
		w.abort()
		return "", mapStoreErr(err)
	}
	frame, _ := json.Marshal(approvedFrame{
		T: "approved", DeviceID: desktopID, DeviceToken: token, MobileDeviceID: mobile.ID,
		MobileName: mobile.Name, MobilePublicKey: mobile.PublicKey, UserEmail: user.Email,
	})
	if err := w.deliver(frame); err != nil {
		// The desktop never learned the result: undo so no orphaned
		// desktop device or pair remains. The pairing stays consumed.
		if uerr := s.store.UndoApproval(context.WithoutCancel(ctx), desktopID, mobile.ID, created); uerr != nil {
			s.log.Error("undo approval failed", "pairing_id", pairingID, "err", uerr)
		}
		return "", apierr.DesktopOffline("the desktop disconnected")
	}
	s.hub.Paired(desktopID, mobile.ID)
	s.log.Info("pairing approved", "pairing_id", pairingID, "desktop_id", desktopID, "mobile_id", mobile.ID, "new_desktop", created)
	return desktopID, nil
}

func mapStoreErr(err error) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return apierr.NotFound("unknown pairing")
	case errors.Is(err, store.ErrConflict):
		return apierr.Conflict("pairing already claimed or used")
	case errors.Is(err, store.ErrExpired):
		return apierr.Expired("pairing expired")
	case errors.Is(err, store.ErrForbidden):
		return apierr.Forbidden("not allowed")
	}
	return err
}

// CleanName validates a device or desktop name: 1..MaxNameRunes runes, no
// control characters.
func CleanName(name, field string) (string, error) {
	n := 0
	for _, r := range name {
		n++
		if r < 0x20 || r == 0x7f {
			return "", apierr.BadRequest(field + " contains control characters")
		}
	}
	if n == 0 || n > MaxNameRunes {
		return "", apierr.BadRequest(field + " must be 1-64 characters")
	}
	return name, nil
}

// Cleanup deletes expired pairings.
func (s *Service) Cleanup(ctx context.Context) {
	n, err := s.store.DeleteExpiredPairings(ctx, time.Now().UnixMilli())
	if err != nil {
		s.log.Error("pairing cleanup failed", "err", err)
		return
	}
	if n > 0 {
		s.log.Info("expired pairings removed", "count", n)
	}
}

// RunCleanup runs Cleanup every interval until ctx is done.
func (s *Service) RunCleanup(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Cleanup(ctx)
		}
	}
}

// ---- waiting desktops (§5.2) ----

type delivery struct {
	frame []byte // nil = abort
	ack   chan error
}

type waiter struct {
	deliveries chan delivery
	replaced   chan struct{}
	once       sync.Once
}

var errAborted = errors.New("aborted")

func (w *waiter) deliver(frame []byte) error {
	ack := make(chan error, 1)
	w.deliveries <- delivery{frame: frame, ack: ack} // buffered, taken waiters get exactly one
	select {
	case err := <-ack:
		return err
	case <-time.After(deliverTimeout):
		return errors.New("deliver timeout")
	}
}

func (w *waiter) abort() { w.deliveries <- delivery{ack: make(chan error, 1)} }

// take removes and returns the waiter for the pairing, if any. Once taken,
// the waiter receives exactly one delivery.
func (s *Service) take(id string) *waiter {
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.waiters[id]
	delete(s.waiters, id)
	return w
}

// release unregisters w if it is still registered; false means it was taken.
func (s *Service) release(id string, w *waiter) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.waiters[id] == w {
		delete(s.waiters, id)
		return true
	}
	return false
}

// IsWaiting reports whether a desktop waits on the pairing (for tests).
func (s *Service) IsWaiting(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.waiters[id] != nil
}

// CloseAll disconnects all waiting desktops (shutdown).
func (s *Service) CloseAll() {
	s.mu.Lock()
	ws := s.waiters
	s.waiters = map[string]*waiter{}
	s.mu.Unlock()
	for _, w := range ws {
		w.once.Do(func() { close(w.replaced) })
	}
}

// Wait blocks until all wait handlers have returned or the timeout passes.
func (s *Service) Wait(timeout time.Duration) bool { return hub.WaitGroupTimeout(&s.wg, timeout) }

// ServeWait handles GET /v1/pairings/{id}/wait.
func (s *Service) ServeWait(w http.ResponseWriter, r *http.Request, pairingID string) {
	conn, err := hub.Upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	s.wg.Add(1)
	defer s.wg.Done()
	defer conn.Close()
	conn.SetReadLimit(4096)
	conn.SetReadDeadline(time.Now().Add(s.AuthTimeout))
	_, data, err := conn.ReadMessage()
	if err != nil {
		return
	}
	var f struct {
		T      string `json:"t"`
		Secret string `json:"secret"`
	}
	if json.Unmarshal(data, &f) != nil || f.T != "auth" || f.Secret == "" || len(f.Secret) > 128 {
		hub.RejectAndClose(conn, "unauthorized")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	p, err := s.store.PairingByID(ctx, pairingID)
	cancel()
	if err != nil || !auth.HashEqual(auth.Hash(f.Secret), p.WaitSecretHash) {
		hub.RejectAndClose(conn, "unauthorized")
		return
	}
	writeClose := func(frame []byte, code int) {
		conn.SetWriteDeadline(time.Now().Add(hub.WriteWait))
		if frame != nil {
			conn.WriteMessage(websocket.TextMessage, frame)
		}
		conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, ""), time.Now().Add(hub.WriteWait))
	}
	expiredFrame := []byte(`{"t":"expired"}`)
	remaining := time.Until(time.UnixMilli(p.ExpiresAt))
	if p.ConsumedAt != nil || remaining <= 0 {
		writeClose(expiredFrame, websocket.CloseNormalClosure)
		return
	}

	wt := &waiter{deliveries: make(chan delivery, 1), replaced: make(chan struct{})}
	s.mu.Lock()
	old := s.waiters[pairingID]
	s.waiters[pairingID] = wt
	s.mu.Unlock()
	if old != nil {
		old.once.Do(func() { close(old.replaced) })
	}
	s.log.Info("desktop waiting", "pairing_id", pairingID)

	gone := make(chan struct{})
	go func() {
		defer close(gone)
		extend := func() { conn.SetReadDeadline(time.Now().Add(s.ReadDeadline)) }
		extend()
		conn.SetPongHandler(func(string) error { extend(); return nil })
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
			extend()
		}
	}()
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	ping := time.NewTicker(s.PingInterval)
	defer ping.Stop()

	handle := func(d delivery) {
		if d.frame == nil {
			writeClose(hub.ErrorFrame("internal"), websocket.CloseInternalServerErr)
			d.ack <- errAborted
			return
		}
		conn.SetWriteDeadline(time.Now().Add(hub.WriteWait))
		err := conn.WriteMessage(websocket.TextMessage, d.frame)
		select {
		case <-gone: // the desktop vanished; the write may have been lost
			if err == nil {
				err = errors.New("desktop disconnected")
			}
		default:
		}
		d.ack <- err
		if err == nil {
			writeClose(nil, websocket.CloseNormalClosure)
		}
	}
	// awaitTaken waits for the single delivery promised to a taken waiter.
	awaitTaken := func() {
		select {
		case d := <-wt.deliveries:
			handle(d)
		case <-time.After(deliverTimeout + time.Second):
		}
	}

	for {
		select {
		case d := <-wt.deliveries:
			handle(d)
			return
		case <-timer.C:
			if s.release(pairingID, wt) {
				writeClose(expiredFrame, websocket.CloseNormalClosure)
				s.log.Info("pairing expired while waiting", "pairing_id", pairingID)
			} else {
				awaitTaken()
			}
			return
		case <-gone:
			if !s.release(pairingID, wt) {
				awaitTaken() // approve is in flight; it will see the failed write
			}
			return
		case <-wt.replaced:
			writeClose(nil, hub.CloseReplaced)
			return
		case <-ping.C:
			if conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(hub.WriteWait)) != nil {
				if !s.release(pairingID, wt) {
					awaitTaken()
				}
				return
			}
		}
	}
}
