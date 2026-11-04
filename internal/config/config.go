// Package config loads the relay configuration from the environment, with
// command-line flags taking precedence.
package config

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"strings"
)

// Config is the relay configuration.
type Config struct {
	ListenAddr     string // LISTEN_ADDR, default 127.0.0.1:8080
	DBPath         string // DB_PATH, default ./jcrelay.db
	GoogleClientID string // GOOGLE_CLIENT_ID: the Google *web* client ID (ID token aud)
	DevLogin       bool   // DEV_LOGIN=1 enables POST /v1/auth/dev (loopback only)
	TrustProxy     bool   // TRUST_PROXY=1: take the client IP from X-Forwarded-For (rate limits only)
}

// Load reads env (via getenv) and then args (flags) and validates the result.
func Load(args []string, getenv func(string) string) (Config, error) {
	c := Config{
		ListenAddr:     envOr(getenv, "LISTEN_ADDR", "127.0.0.1:8080"),
		DBPath:         envOr(getenv, "DB_PATH", "jcrelay.db"),
		GoogleClientID: getenv("GOOGLE_CLIENT_ID"),
		DevLogin:       truthy(getenv("DEV_LOGIN")),
		TrustProxy:     truthy(getenv("TRUST_PROXY")),
	}
	fs := flag.NewFlagSet("jcrelay", flag.ContinueOnError)
	fs.StringVar(&c.ListenAddr, "listen", c.ListenAddr, "listen address (LISTEN_ADDR)")
	fs.StringVar(&c.DBPath, "db", c.DBPath, "SQLite database path (DB_PATH)")
	fs.StringVar(&c.GoogleClientID, "google-client-id", c.GoogleClientID, "Google web client ID used as ID token audience (GOOGLE_CLIENT_ID)")
	fs.BoolVar(&c.DevLogin, "dev-login", c.DevLogin, "enable POST /v1/auth/dev; loopback only (DEV_LOGIN)")
	fs.BoolVar(&c.TrustProxy, "trust-proxy", c.TrustProxy, "use X-Forwarded-For for rate limits (TRUST_PROXY)")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Validate checks invariants. DEV_LOGIN is refused unless the relay listens
// on a loopback address only.
func (c Config) Validate() error {
	if c.ListenAddr == "" {
		return errors.New("LISTEN_ADDR is empty")
	}
	if c.DBPath == "" {
		return errors.New("DB_PATH is empty")
	}
	if c.DevLogin && !IsLoopback(c.ListenAddr) {
		return fmt.Errorf("DEV_LOGIN is enabled but LISTEN_ADDR %q is not a loopback address; refusing to start", c.ListenAddr)
	}
	if !c.DevLogin && c.GoogleClientID == "" {
		return errors.New("GOOGLE_CLIENT_ID is required (or DEV_LOGIN=1 for local development)")
	}
	return nil
}

// IsLoopback reports whether addr (host:port) binds to loopback only. An
// empty host (":8080") binds all interfaces and is not loopback.
func IsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func envOr(getenv func(string) string, key, def string) string {
	if v := getenv(key); v != "" {
		return v
	}
	return def
}

func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
