// Package api is the relay's HTTP surface (docs/protocol.md §4).
package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/mohammadirham37/jenderalcode_backend/internal/apierr"
	"github.com/mohammadirham37/jenderalcode_backend/internal/auth"
	"github.com/mohammadirham37/jenderalcode_backend/internal/hub"
	"github.com/mohammadirham37/jenderalcode_backend/internal/pairing"
	"github.com/mohammadirham37/jenderalcode_backend/internal/store"
)

// MaxBodyBytes caps JSON request bodies.
const MaxBodyBytes = 16 << 10

// Deps wires the handlers.
type Deps struct {
	Store    *store.Store
	Hub      *hub.Hub
	Pairing  *pairing.Service
	Verifier auth.IDTokenVerifier // nil disables /v1/auth/google
	DevLogin bool
	Log      *slog.Logger

	TrustProxy bool
	AuthLimit  *Limiter // per IP, /v1/auth/*
	PairLimit  *Limiter // per IP, /v1/pairings*
}

type server struct{ Deps }

// NewRouter builds the HTTP handler.
func NewRouter(d Deps) http.Handler {
	s := &server{d}
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.NotFound(func(w http.ResponseWriter, _ *http.Request) { writeErr(w, apierr.NotFound("no such endpoint")) })
	r.MethodNotAllowed(func(w http.ResponseWriter, _ *http.Request) {
		writeErr(w, &apierr.Error{Status: http.StatusMethodNotAllowed, Code: "bad_request", Message: "method not allowed"})
	})

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, "ok")
	})

	required := auth.Middleware(d.Store, false, s.authFail)
	optional := auth.Middleware(d.Store, true, s.authFail)

	r.Route("/v1", func(r chi.Router) {
		r.Route("/auth", func(r chi.Router) {
			r.Use(s.limitIP(d.AuthLimit))
			r.Post("/google", s.authGoogle)
			if d.DevLogin {
				r.Post("/dev", s.authDev)
			}
		})
		r.Route("/pairings", func(r chi.Router) {
			r.Use(s.limitIP(d.PairLimit))
			r.With(optional).Post("/", s.createPairing)
			r.Get("/{id}/wait", func(w http.ResponseWriter, r *http.Request) {
				d.Pairing.ServeWait(w, r, chi.URLParam(r, "id"))
			})
			r.With(required).Post("/claim", s.claimPairing)
			r.With(required).Post("/{id}/approve", s.approvePairing)
		})
		r.With(required).Get("/peers", s.listPeers)
		r.With(required).Delete("/peers/{device_id}", s.deletePeer)
		r.With(required).Delete("/devices/{device_id}", s.deleteDevice)
		r.Get("/ws", d.Hub.ServeWS)
	})
	return r
}

func (s *server) limitIP(l *Limiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if l == nil {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !l.Allow(ClientIP(r, s.TrustProxy)) {
				writeErr(w, apierr.RateLimited("too many requests"))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (s *server) authFail(w http.ResponseWriter, _ error) {
	writeErr(w, apierr.Unauthorized("invalid or missing device token"))
}

// ---- helpers ----

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, e *apierr.Error) {
	writeJSON(w, e.Status, map[string]string{"error": e.Code, "message": e.Message})
}

func (s *server) fail(w http.ResponseWriter, r *http.Request, err error) {
	e := apierr.From(err)
	if e.Code == "internal" {
		s.Log.Error("request failed", "path", r.URL.Path, "err", err)
	}
	writeErr(w, e)
}

// decode reads a JSON body capped at MaxBodyBytes. An empty body decodes as {}.
func decode(w http.ResponseWriter, r *http.Request, v any) error {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
	if err != nil {
		return apierr.BadRequest("request body too large or unreadable")
	}
	if len(body) == 0 {
		body = []byte("{}")
	}
	if err := json.Unmarshal(body, v); err != nil {
		return apierr.BadRequest("invalid JSON body")
	}
	return nil
}

func ctxTimeout(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), 10*time.Second)
}

func device(r *http.Request) store.Device {
	d, _ := auth.DeviceFrom(r.Context())
	return d
}

// ---- auth ----

type loginResponse struct {
	DeviceID    string   `json:"device_id"`
	DeviceToken string   `json:"device_token"`
	User        userJSON `json:"user"`
}

type userJSON struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

func (s *server) authGoogle(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDToken    string `json:"id_token"`
		DeviceName string `json:"device_name"`
		PublicKey  string `json:"public_key"`
	}
	if err := decode(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if s.Verifier == nil {
		s.fail(w, r, apierr.NotFound("google login is not configured"))
		return
	}
	if req.IDToken == "" {
		s.fail(w, r, apierr.BadRequest("id_token is required"))
		return
	}
	ctx, cancel := ctxTimeout(r)
	defer cancel()
	id, err := s.Verifier.Verify(ctx, req.IDToken)
	if err != nil {
		s.Log.Info("google login rejected", "err", err) // idtoken errors never contain the token
		s.fail(w, r, apierr.Unauthorized("invalid Google ID token"))
		return
	}
	s.login(w, r, id.Subject, id.Email, id.Name, req.DeviceName, req.PublicKey)
}

func (s *server) authDev(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email      string `json:"email"`
		DeviceName string `json:"device_name"`
		PublicKey  string `json:"public_key"`
	}
	if err := decode(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	at := -1
	for i, c := range req.Email {
		if c == '@' {
			at = i
		}
	}
	if at <= 0 || at == len(req.Email)-1 || len(req.Email) > 254 {
		s.fail(w, r, apierr.BadRequest("a valid email is required"))
		return
	}
	s.login(w, r, "dev:"+strings.ToLower(req.Email), req.Email, req.Email[:at], req.DeviceName, req.PublicKey)
}

func (s *server) login(w http.ResponseWriter, r *http.Request, sub, email, name, deviceName, publicKey string) {
	if err := auth.ValidatePublicKey(publicKey); err != nil {
		s.fail(w, r, apierr.BadRequest(err.Error()))
		return
	}
	deviceName, err := pairing.CleanName(deviceName, "device_name")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if name == "" {
		name = email
	}
	ctx, cancel := ctxTimeout(r)
	defer cancel()
	now := time.Now().UnixMilli()
	u, err := s.Store.UpsertUser(ctx, sub, email, name, now)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	token := auth.NewToken()
	id, reused, err := s.Store.LoginMobile(ctx, u.ID, deviceName, publicKey, auth.Hash(token), now)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if reused {
		s.Hub.Kick(id) // the old token no longer authenticates
	}
	s.Log.Info("mobile login", "device_id", id, "user_id", u.ID, "reused", reused)
	writeJSON(w, http.StatusOK, loginResponse{DeviceID: id, DeviceToken: token, User: userJSON{u.ID, u.Email, u.Name}})
}

// ---- pairings ----

func (s *server) createPairing(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PublicKey string `json:"public_key"`
		Name      string `json:"name"`
	}
	if err := decode(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	var existing *store.Device
	if d, ok := auth.DeviceFrom(r.Context()); ok {
		existing = &d
	}
	ctx, cancel := ctxTimeout(r)
	defer cancel()
	res, err := s.Pairing.Create(ctx, req.PublicKey, req.Name, existing)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *server) claimPairing(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}
	if err := decode(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	ctx, cancel := ctxTimeout(r)
	defer cancel()
	res, err := s.Pairing.Claim(ctx, device(r), req.Code)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *server) approvePairing(w http.ResponseWriter, r *http.Request) {
	var req struct{}
	if err := decode(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	desktopID, err := s.Pairing.Approve(ctx, device(r), chi.URLParam(r, "id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"desktop_device_id": desktopID})
}

// ---- peers and devices ----

type peerJSON struct {
	DeviceID  string `json:"device_id"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
	Online    bool   `json:"online"`
	LastSeen  *int64 `json:"last_seen"`
}

func (s *server) listPeers(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := ctxTimeout(r)
	defer cancel()
	peers, err := s.Store.Peers(ctx, device(r).ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]peerJSON, 0, len(peers))
	for _, p := range peers {
		out = append(out, peerJSON{p.ID, p.Kind, p.Name, p.PublicKey, s.Hub.Online(p.ID), p.LastSeen})
	}
	writeJSON(w, http.StatusOK, map[string]any{"peers": out})
}

func (s *server) deletePeer(w http.ResponseWriter, r *http.Request) {
	me := device(r)
	peer := chi.URLParam(r, "device_id")
	ctx, cancel := ctxTimeout(r)
	defer cancel()
	if err := s.Store.DeletePair(ctx, me.ID, peer); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			err = apierr.NotFound("no such peer")
		}
		s.fail(w, r, err)
		return
	}
	s.Hub.Unpaired(me.ID, peer)
	s.Log.Info("unpaired", "device_id", me.ID, "peer_id", peer)
	writeJSON(w, http.StatusOK, struct{}{})
}

func (s *server) deleteDevice(w http.ResponseWriter, r *http.Request) {
	me := device(r)
	target := chi.URLParam(r, "device_id")
	ctx, cancel := ctxTimeout(r)
	defer cancel()
	d, err := s.Store.DeviceByID(ctx, target)
	if errors.Is(err, store.ErrNotFound) {
		s.fail(w, r, apierr.NotFound("no such device"))
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if d.UserID != me.UserID {
		s.fail(w, r, apierr.Forbidden("device belongs to another account"))
		return
	}
	peers, err := s.Store.RevokeDevice(ctx, d.ID, time.Now().UnixMilli())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.Hub.Revoked(d.ID, peers)
	s.Log.Info("device revoked", "device_id", d.ID, "by", me.ID, "peers", len(peers))
	writeJSON(w, http.StatusOK, struct{}{})
}
