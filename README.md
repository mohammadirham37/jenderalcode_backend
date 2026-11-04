# jcrelay: JenderalCode remote relay

A small Go server that lets the JenderalCode mobile app control the
JenderalCode desktop app. Both connect outbound to the relay; the relay
authenticates devices (Google sign-in on the phone, pairing codes for the
desktop) and forwards **end-to-end-encrypted** messages between paired
devices. It never sees plaintext and holds no keys that could decrypt it.

The protocol is `docs/protocol.md` (a verbatim copy of the desktop repo's
`docs/REMOTE_PROTOCOL.md`; change it there first).

## Configuration

| Env var | Flag | Default | Meaning |
|---|---|---|---|
| `LISTEN_ADDR` | `-listen` | `127.0.0.1:8080` | HTTP listen address |
| `DB_PATH` | `-db` | `jcrelay.db` | SQLite file (WAL mode) |
| `GOOGLE_CLIENT_ID` | `-google-client-id` | (required unless `DEV_LOGIN`) | Google **web** client ID, checked as the ID token `aud` |
| `DEV_LOGIN` | `-dev-login` | off | Enables `POST /v1/auth/dev` (login by email, no Google). Refused unless `LISTEN_ADDR` is loopback |
| `TRUST_PROXY` | `-trust-proxy` | off | Use the last `X-Forwarded-For` entry as client IP for rate limits (set behind Caddy) |

## Run locally

```bash
DEV_LOGIN=1 DB_PATH=/tmp/jcrelay-dev.db go run ./cmd/jcrelay
curl -s http://127.0.0.1:8080/healthz
# fake phone login (public_key = b64u of 32 bytes)
curl -s -X POST http://127.0.0.1:8080/v1/auth/dev \
  -d '{"email":"me@example.com","device_name":"Test phone","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}'
```

## Test

```bash
make test   # go test ./... -race
make lint   # go vet ./...
```

The integration tests in `internal/api` run the full pairing and messaging
flow against an `httptest` server with real WebSocket clients.

## Layout

- `cmd/jcrelay`: config, wiring, graceful shutdown
- `internal/config`: env/flags, DEV_LOGIN loopback guard
- `internal/store`: SQLite + embedded migrations
- `internal/auth`: Google ID token verification, device tokens (SHA-256 hashes only), Bearer middleware
- `internal/pairing`: create / wait / claim / approve
- `internal/hub`: `/v1/ws` connections, routing, presence
- `internal/api`: chi router, handlers, rate limits
- `deploy/`: systemd unit, Caddyfile, deployment notes
