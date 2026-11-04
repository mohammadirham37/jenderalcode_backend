// Command jcrelay is the JenderalCode remote relay: it authenticates devices
// and forwards end-to-end-encrypted messages between paired desktops and
// phones. It never decrypts anything. Protocol: docs/protocol.md.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mohammadirham37/jenderalcode_backend/internal/api"
	"github.com/mohammadirham37/jenderalcode_backend/internal/auth"
	"github.com/mohammadirham37/jenderalcode_backend/internal/config"
	"github.com/mohammadirham37/jenderalcode_backend/internal/hub"
	"github.com/mohammadirham37/jenderalcode_backend/internal/pairing"
	"github.com/mohammadirham37/jenderalcode_backend/internal/store"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := config.Load(os.Args[1:], os.Getenv)
	if err != nil {
		return err
	}
	if cfg.DevLogin {
		log.Warn("!!! DEV_LOGIN IS ENABLED: anyone reaching this relay can log in as any email via POST /v1/auth/dev. Never use this in production. !!!")
	}

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()

	msgLimit := api.NewLimiter(30, 120)  // per device, WebSocket msg frames
	authLimit := api.NewLimiter(0.2, 10) // per IP: 10 at once, then 12/min
	pairLimit := api.NewLimiter(0.5, 20) // per IP: 20 at once, then 30/min

	h := hub.New(st, log, msgLimit.Allow)
	ps := pairing.New(st, h, log)

	var verifier auth.IDTokenVerifier
	if cfg.GoogleClientID != "" {
		verifier = auth.NewGoogleVerifier(cfg.GoogleClientID)
	}

	router := api.NewRouter(api.Deps{
		Store: st, Hub: h, Pairing: ps, Verifier: verifier, DevLogin: cfg.DevLogin, Log: log,
		TrustProxy: cfg.TrustProxy, AuthLimit: authLimit, PairLimit: pairLimit,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go ps.RunCleanup(ctx, time.Minute)
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				msgLimit.Sweep()
				authLimit.Sweep()
				pairLimit.Sweep()
			}
		}
	}()

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second, // cleared by the WebSocket library after upgrade
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	errc := make(chan error, 1)
	go func() {
		log.Info("relay listening", "addr", cfg.ListenAddr, "google_login", verifier != nil, "dev_login", cfg.DevLogin, "trust_proxy", cfg.TrustProxy)
		errc <- srv.ListenAndServe()
	}()

	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		log.Info("shutting down")
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = srv.Shutdown(sctx)
	h.CloseAll()
	ps.CloseAll()
	// Handlers still in their auth phase end within hub.AuthTimeout.
	if !h.Wait(hub.AuthTimeout+time.Second) || !ps.Wait(time.Second) {
		log.Warn("some websocket handlers did not stop in time")
	}
	return err
}
