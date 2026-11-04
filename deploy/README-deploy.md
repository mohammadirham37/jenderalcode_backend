# Deploying jcrelay

The relay is a single static binary listening on loopback behind Caddy.

## 1. Build (on any machine)

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
  -o bin/jcrelay-linux-amd64 ./cmd/jcrelay
# or: make build-linux
```

## 2. Copy to the server

```bash
scp bin/jcrelay-linux-amd64 deploy/jcrelay.service <user>@<build-host>:/tmp/
ssh <user>@<build-host>
sudo install -m 0755 /tmp/jcrelay-linux-amd64 /usr/local/bin/jcrelay
sudo install -m 0644 /tmp/jcrelay.service /etc/systemd/system/jcrelay.service
```

## 3. Configure

```bash
sudo install -d -m 0755 /etc/jcrelay
echo 'GOOGLE_CLIENT_ID=<google-web-client-id>' | sudo tee /etc/jcrelay/jcrelay.env >/dev/null
sudo chmod 0600 /etc/jcrelay/jcrelay.env
```

`GOOGLE_CLIENT_ID` is the **web** OAuth client ID: Android `google_sign_in`
issues ID tokens whose `aud` is the web client ID passed as `serverClientId`.
Never set `DEV_LOGIN` in production (the relay refuses it on non-loopback
addresses anyway).

The database lives in `/var/lib/jcrelay/relay.db` (systemd `StateDirectory`,
owned by the dynamic service user).

## 4. Enable

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now jcrelay
systemctl status jcrelay
curl -s http://127.0.0.1:8080/healthz   # ok
journalctl -u jcrelay -f
```

## 5. Caddy

Copy `Caddyfile.example` into `/etc/caddy/Caddyfile` (replace
`<relay-domain>`), then `sudo systemctl reload caddy`. Check
`curl -s https://<relay-domain>/healthz`.

## Upgrading

Copy the new binary over `/usr/local/bin/jcrelay` and
`sudo systemctl restart jcrelay`. Migrations run automatically at start.
Clients reconnect on their own (backoff 1 s → 30 s).

## Backup

`sqlite3 /var/lib/jcrelay/relay.db ".backup /root/relay-backup.db"`
(the DB only holds accounts, device public keys, token hashes and pairs).
