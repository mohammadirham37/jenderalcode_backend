package api_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/mohammadirham37/jenderalcode_backend/internal/api"
	"github.com/mohammadirham37/jenderalcode_backend/internal/auth"
	"github.com/mohammadirham37/jenderalcode_backend/internal/hub"
	"github.com/mohammadirham37/jenderalcode_backend/internal/pairing"
)

func TestHealthz(t *testing.T) {
	e := newEnv(t)
	resp, err := e.srv.Client().Get(e.srv.URL + "/healthz")
	if err != nil || resp.StatusCode != 200 {
		t.Fatal(err, resp)
	}
}

func TestFullPairingFlow(t *testing.T) {
	e := newEnv(t)
	phone := e.googleLogin("google-alice", "Pixel")

	desktopPK := auth.RandomB64U(32)
	p, wait := e.startPairing("", desktopPK, "Work laptop")
	if len(p["code"].(string)) != 22 || len(p["wait_secret"].(string)) != 43 {
		t.Fatalf("bad code/secret lengths: %v", p)
	}
	if exp := int64(p["expires_at"].(float64)); exp < time.Now().Add(110*time.Second).UnixMilli() || exp > time.Now().Add(121*time.Second).UnixMilli() {
		t.Fatalf("expires_at not ~120 s ahead: %d", exp)
	}

	claim := e.mustDo(200, "POST", "/v1/pairings/claim", phone.token, obj{"code": p["code"]})
	if claim["pairing_id"] != p["pairing_id"] || claim["desktop_name"] != "Work laptop" ||
		claim["desktop_public_key"] != desktopPK || claim["expires_at"] != p["expires_at"] {
		t.Fatalf("claim: %v", claim)
	}
	appr := e.mustDo(200, "POST", "/v1/pairings/"+p["pairing_id"].(string)+"/approve", phone.token, obj{})
	desktopID := appr["desktop_device_id"].(string)

	a := readType(t, wait, "approved")
	if a["device_id"] != desktopID || a["mobile_device_id"] != phone.id || a["mobile_name"] != "Pixel" ||
		a["mobile_public_key"] != phone.pk || a["user_email"] != "alice@example.com" {
		t.Fatalf("approved: %v", a)
	}
	desktopTok, _ := a["device_token"].(string)
	if len(desktopTok) != 43 {
		t.Fatalf("device_token: %v", a["device_token"])
	}
	expectClose(t, wait)

	// The code is single use.
	e.expectErr(409, "conflict", "POST", "/v1/pairings/claim", phone.token, obj{"code": p["code"]})

	dc, dready := e.connect(desktopTok)
	if dready["device_id"] != desktopID {
		t.Fatalf("ready: %v", dready)
	}
	peers := dready["peers"].([]any)
	if len(peers) != 1 || peers[0].(obj)["device_id"] != phone.id || peers[0].(obj)["online"] != false {
		t.Fatalf("desktop ready peers: %v", peers)
	}
	mc, mready := e.connect(phone.token)
	peers = mready["peers"].([]any)
	if len(peers) != 1 || peers[0].(obj)["device_id"] != desktopID || peers[0].(obj)["online"] != true {
		t.Fatalf("mobile ready peers: %v", peers)
	}
	pr := readType(t, dc, "presence")
	if pr["device_id"] != phone.id || pr["online"] != true {
		t.Fatalf("presence: %v", pr)
	}

	send(t, mc, obj{"t": "msg", "to": desktopID, "id": "m-1", "body": "c2VhbGVk"})
	m := readType(t, dc, "msg")
	if m["from"] != phone.id || m["id"] != "m-1" || m["body"] != "c2VhbGVk" || m["to"] != nil {
		t.Fatalf("desktop got %v", m)
	}
	// A spoofed "from" is ignored: the relay fills it in.
	send(t, dc, obj{"t": "msg", "to": phone.id, "from": "someone-else", "id": "m-2", "body": "cmVwbHk"})
	m = readType(t, mc, "msg")
	if m["from"] != desktopID || m["id"] != "m-2" || m["body"] != "cmVwbHk" {
		t.Fatalf("mobile got %v", m)
	}

	list := e.mustDo(200, "GET", "/v1/peers", phone.token, nil)["peers"].([]any)
	if len(list) != 1 {
		t.Fatalf("peers: %v", list)
	}
	pe := list[0].(obj)
	if pe["device_id"] != desktopID || pe["kind"] != "desktop" || pe["name"] != "Work laptop" ||
		pe["public_key"] != desktopPK || pe["online"] != true || pe["last_seen"] == nil {
		t.Fatalf("peer: %v", pe)
	}
}

func TestDevLoginAndRelogin(t *testing.T) {
	e := newEnv(t)
	a := e.devLogin("dev@example.com", "Phone")
	out := e.mustDo(200, "POST", "/v1/auth/dev", "", obj{"email": "dev@example.com", "device_name": "Phone 2", "public_key": a.pk})
	if out["device_id"] != a.id || out["device_token"] == a.token {
		t.Fatalf("relogin with same key should reuse id and rotate token: %v", out)
	}
	user := out["user"].(obj)
	if user["email"] != "dev@example.com" || user["id"] == "" {
		t.Fatalf("user: %v", user)
	}
	e.expectErr(401, "unauthorized", "GET", "/v1/peers", a.token, nil)
	e.mustDo(200, "GET", "/v1/peers", out["device_token"].(string), nil)

	// A different key gives a new device.
	b := e.devLogin("dev@example.com", "Tablet")
	if b.id == a.id {
		t.Fatal("new key reused device id")
	}
}

func TestDevLoginDisabledByDefault(t *testing.T) {
	e := newEnv(t)
	// A router without DevLogin or a verifier: neither login is routed.
	h := api.NewRouter(api.Deps{Store: e.st, Hub: e.hub, Pairing: e.ps, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	rec := doRecorder(h, "POST", "/v1/auth/dev", `{"email":"x@example.com","device_name":"p","public_key":"`+auth.RandomB64U(32)+`"}`)
	if rec.Code != 404 || !strings.Contains(rec.Body.String(), `"not_found"`) {
		t.Fatalf("dev login without DEV_LOGIN: %d %s", rec.Code, rec.Body)
	}
	rec = doRecorder(h, "POST", "/v1/auth/google", `{"id_token":"google-alice","device_name":"p","public_key":"`+auth.RandomB64U(32)+`"}`)
	if rec.Code != 404 {
		t.Fatalf("google login without client id: %d", rec.Code)
	}
}

func TestGoogleLoginRejectsBadToken(t *testing.T) {
	e := newEnv(t)
	e.expectErr(401, "unauthorized", "POST", "/v1/auth/google", "", obj{"id_token": "forged", "device_name": "p", "public_key": auth.RandomB64U(32)})
}

func TestInputValidation(t *testing.T) {
	e := newEnv(t)
	pk := auth.RandomB64U(32)
	bad := []obj{
		{"email": "a@example.com", "device_name": "p", "public_key": "short"},
		{"email": "a@example.com", "device_name": "p", "public_key": pk + "="},
		{"email": "a@example.com", "device_name": "p", "public_key": auth.RandomB64U(31)},
		{"email": "a@example.com", "device_name": "", "public_key": pk},
		{"email": "a@example.com", "device_name": strings.Repeat("x", 65), "public_key": pk},
		{"email": "a@example.com", "device_name": "a\nb", "public_key": pk},
		{"email": "not-an-email", "device_name": "p", "public_key": pk},
	}
	for _, b := range bad {
		e.expectErr(400, "bad_request", "POST", "/v1/auth/dev", "", b)
	}
	e.mustDo(200, "POST", "/v1/auth/dev", "", obj{"email": "a@example.com", "device_name": strings.Repeat("é", 64), "public_key": pk})
	e.expectErr(400, "bad_request", "POST", "/v1/pairings", "", obj{"public_key": "x", "name": "n"})
	e.expectErr(400, "bad_request", "POST", "/v1/pairings", "", obj{"public_key": pk, "name": strings.Repeat("x", 65)})
	big := []byte(`{"public_key":"` + pk + `","name":"n","pad":"` + strings.Repeat("x", api.MaxBodyBytes) + `"}`)
	e.expectErr(400, "bad_request", "POST", "/v1/pairings", "", big)
	e.expectErr(400, "bad_request", "POST", "/v1/pairings", "", []byte("{not json"))
	e.expectErr(401, "unauthorized", "POST", "/v1/pairings", "garbage-token", obj{"public_key": pk, "name": "n"})
	e.expectErr(401, "unauthorized", "GET", "/v1/peers", "", nil)
}

func TestClaimConflictAndSecondPhone(t *testing.T) {
	e := newEnv(t)
	phone1 := e.googleLogin("google-alice", "P1")
	phone2 := e.googleLogin("google-bob", "P2")
	p, _ := e.startPairing("", auth.RandomB64U(32), "Laptop")
	e.mustDo(200, "POST", "/v1/pairings/claim", phone1.token, obj{"code": p["code"]})
	// Claiming again by the same phone is idempotent.
	e.mustDo(200, "POST", "/v1/pairings/claim", phone1.token, obj{"code": p["code"]})
	e.expectErr(409, "conflict", "POST", "/v1/pairings/claim", phone2.token, obj{"code": p["code"]})
	// Only the claimer may approve.
	e.expectErr(403, "forbidden", "POST", "/v1/pairings/"+p["pairing_id"].(string)+"/approve", phone2.token, obj{})
	e.expectErr(404, "not_found", "POST", "/v1/pairings/claim", phone1.token, obj{"code": auth.RandomB64U(16)})
	e.expectErr(404, "not_found", "POST", "/v1/pairings/nope/approve", phone1.token, obj{})
}

func TestExpiredPairing(t *testing.T) {
	e := newEnv(t, envOpts{tweak: func(_ *hub.Hub, ps *pairing.Service) { ps.TTL = 300 * time.Millisecond }})
	phone := e.googleLogin("google-alice", "P1")

	// A waiting desktop gets {"t":"expired"} when the code runs out.
	p, w := e.startPairing("", auth.RandomB64U(32), "Laptop")
	if f := readType(t, w, "expired"); len(f) != 1 {
		t.Fatalf("expired frame has extra fields: %v", f)
	}
	e.expectErr(410, "expired", "POST", "/v1/pairings/claim", phone.token, obj{"code": p["code"]})

	// Claimed in time, approved too late.
	p2 := e.mustDo(200, "POST", "/v1/pairings", "", obj{"public_key": auth.RandomB64U(32), "name": "L"})
	e.mustDo(200, "POST", "/v1/pairings/claim", phone.token, obj{"code": p2["code"]})
	time.Sleep(350 * time.Millisecond)
	e.expectErr(410, "expired", "POST", "/v1/pairings/"+p2["pairing_id"].(string)+"/approve", phone.token, obj{})

	// Waiting on an already expired pairing answers expired at once.
	w2 := e.dial("/v1/pairings/" + p2["pairing_id"].(string) + "/wait")
	send(t, w2, obj{"t": "auth", "secret": p2["wait_secret"]})
	readType(t, w2, "expired")

	// Cleanup removes them.
	e.ps.Cleanup(t.Context())
	e.expectErr(404, "not_found", "POST", "/v1/pairings/claim", phone.token, obj{"code": p2["code"]})
}

func TestWaitAuth(t *testing.T) {
	e := newEnv(t, envOpts{tweak: func(_ *hub.Hub, ps *pairing.Service) { ps.AuthTimeout = 200 * time.Millisecond }})
	p := e.mustDo(200, "POST", "/v1/pairings", "", obj{"public_key": auth.RandomB64U(32), "name": "L"})
	w := e.dial("/v1/pairings/" + p["pairing_id"].(string) + "/wait")
	send(t, w, obj{"t": "auth", "secret": auth.RandomB64U(32)})
	if f := readType(t, w, "error"); f["error"] != "unauthorized" {
		t.Fatalf("%v", f)
	}
	expectClose(t, w)

	w = e.dial("/v1/pairings/" + p["pairing_id"].(string) + "/wait")
	if code := expectClose(t, w); code == 0 {
		t.Fatal("no close")
	}
	if e.ps.IsWaiting(p["pairing_id"].(string)) {
		t.Fatal("unauthenticated waiter registered")
	}
}

func TestApproveDesktopOffline(t *testing.T) {
	e := newEnv(t)
	phone := e.googleLogin("google-alice", "P1")
	p := e.mustDo(200, "POST", "/v1/pairings", "", obj{"public_key": auth.RandomB64U(32), "name": "L"})
	e.mustDo(200, "POST", "/v1/pairings/claim", phone.token, obj{"code": p["code"]})
	e.expectErr(409, "desktop_offline", "POST", "/v1/pairings/"+p["pairing_id"].(string)+"/approve", phone.token, obj{})

	// A desktop that waited and left is offline too.
	w := e.dial("/v1/pairings/" + p["pairing_id"].(string) + "/wait")
	send(t, w, obj{"t": "auth", "secret": p["wait_secret"]})
	e.waitFor(func() bool { return e.ps.IsWaiting(p["pairing_id"].(string)) })
	w.Close()
	e.waitFor(func() bool { return !e.ps.IsWaiting(p["pairing_id"].(string)) })
	e.expectErr(409, "desktop_offline", "POST", "/v1/pairings/"+p["pairing_id"].(string)+"/approve", phone.token, obj{})

	// Nothing was created: the phone has no peers.
	if peers := e.mustDo(200, "GET", "/v1/peers", phone.token, nil)["peers"].([]any); len(peers) != 0 {
		t.Fatalf("peers: %v", peers)
	}
	// It still works once the desktop waits.
	w = e.dial("/v1/pairings/" + p["pairing_id"].(string) + "/wait")
	send(t, w, obj{"t": "auth", "secret": p["wait_secret"]})
	e.waitFor(func() bool { return e.ps.IsWaiting(p["pairing_id"].(string)) })
	e.mustDo(200, "POST", "/v1/pairings/"+p["pairing_id"].(string)+"/approve", phone.token, obj{})
	readType(t, w, "approved")
}

func TestAddPhoneToExistingDesktop(t *testing.T) {
	e := newEnv(t)
	phone1 := e.googleLogin("google-alice", "P1")
	desktop := e.pairNewDesktop(phone1)
	dc, _ := e.connect(desktop.token)

	// Wrong key or a mobile token are refused.
	e.expectErr(400, "bad_request", "POST", "/v1/pairings", desktop.token, obj{"public_key": auth.RandomB64U(32), "name": "Laptop"})
	e.expectErr(403, "forbidden", "POST", "/v1/pairings", phone1.token, obj{"public_key": phone1.pk, "name": "Laptop"})

	// A phone of another user is forbidden.
	bob := e.googleLogin("google-bob", "Bob phone")
	p, _ := e.startPairing(desktop.token, desktop.pk, "Laptop")
	e.expectErr(403, "forbidden", "POST", "/v1/pairings/claim", bob.token, obj{"code": p["code"]})

	// A second phone of the same user is added, without a new desktop.
	phone2 := e.googleLogin("google-alice2", "P2")
	mc2, _ := e.connect(phone2.token)
	e.mustDo(200, "POST", "/v1/pairings/claim", phone2.token, obj{"code": p["code"]})
	w := e.dial("/v1/pairings/" + p["pairing_id"].(string) + "/wait")
	send(t, w, obj{"t": "auth", "secret": p["wait_secret"]})
	e.waitFor(func() bool { return e.ps.IsWaiting(p["pairing_id"].(string)) })
	out := e.mustDo(200, "POST", "/v1/pairings/"+p["pairing_id"].(string)+"/approve", phone2.token, obj{})
	if out["desktop_device_id"] != desktop.id {
		t.Fatalf("approve: %v", out)
	}
	a := readType(t, w, "approved")
	if a["device_id"] != desktop.id || a["device_token"] != nil || a["mobile_device_id"] != phone2.id {
		t.Fatalf("approved: %v", a)
	}
	if _, present := a["device_token"]; !present {
		t.Fatal("device_token must be present as null")
	}
	// Both were online: they learn about each other.
	if f := readType(t, dc, "presence"); f["device_id"] != phone2.id || f["online"] != true {
		t.Fatalf("%v", f)
	}
	if f := readType(t, mc2, "presence"); f["device_id"] != desktop.id {
		t.Fatalf("%v", f)
	}
	if peers := e.mustDo(200, "GET", "/v1/peers", desktop.token, nil)["peers"].([]any); len(peers) != 2 {
		t.Fatalf("desktop peers: %v", peers)
	}
	// The desktop token still works.
	e.mustDo(200, "GET", "/v1/peers", desktop.token, nil)
}

func TestRouting(t *testing.T) {
	e := newEnv(t)
	phone := e.googleLogin("google-alice", "P1")
	desktop := e.pairNewDesktop(phone)
	stranger := e.googleLogin("google-bob", "Bob")

	mc, _ := e.connect(phone.token)
	sc, _ := e.connect(stranger.token)

	send(t, mc, obj{"t": "msg", "to": desktop.id, "id": "u1", "body": "x"})
	if f := readType(t, mc, "undeliverable"); f["id"] != "u1" || f["to"] != desktop.id || f["reason"] != "offline" {
		t.Fatalf("%v", f)
	}
	send(t, mc, obj{"t": "msg", "to": stranger.id, "id": "u2", "body": "x"})
	if f := readType(t, mc, "undeliverable"); f["reason"] != "not_paired" || f["to"] != stranger.id {
		t.Fatalf("%v", f)
	}
	send(t, sc, obj{"t": "msg", "to": phone.id, "id": "u3", "body": "x"})
	if f := readType(t, sc, "undeliverable"); f["reason"] != "not_paired" {
		t.Fatalf("%v", f)
	}
	send(t, mc, obj{"t": "msg", "to": phone.id, "id": "u4", "body": "x"})
	if f := readType(t, mc, "undeliverable"); f["reason"] != "not_paired" {
		t.Fatalf("self: %v", f)
	}
	send(t, mc, obj{"t": "msg", "to": desktop.id, "body": "x"})
	if f := readType(t, mc, "error"); f["error"] != "bad_request" {
		t.Fatalf("%v", f)
	}
	expectSilence(t, sc, 100*time.Millisecond)
}

func TestPresenceAndReplace(t *testing.T) {
	e := newEnv(t)
	phone := e.googleLogin("google-alice", "P1")
	desktop := e.pairNewDesktop(phone)
	dc, _ := e.connect(desktop.token)
	mc, _ := e.connect(phone.token)
	readType(t, dc, "presence")

	// A second connection for the phone replaces the first with close 4000;
	// the desktop sees it online again and never offline.
	mc2, _ := e.connect(phone.token)
	if code := expectClose(t, mc); code != hub.CloseReplaced {
		t.Fatalf("old connection close code %d", code)
	}
	if f := readType(t, dc, "presence"); f["online"] != true {
		t.Fatalf("%v", f)
	}
	expectSilence(t, dc, 150*time.Millisecond)

	send(t, dc, obj{"t": "msg", "to": phone.id, "id": "r1", "body": "x"})
	readType(t, mc2, "msg")

	mc2.Close()
	if f := readType(t, dc, "presence"); f["device_id"] != phone.id || f["online"] != false {
		t.Fatalf("%v", f)
	}
}

func TestWSAuth(t *testing.T) {
	e := newEnv(t, envOpts{tweak: func(h *hub.Hub, _ *pairing.Service) { h.AuthTimeout = 200 * time.Millisecond }})
	c := e.dial("/v1/ws")
	send(t, c, obj{"t": "auth", "token": "nope"})
	if f := readType(t, c, "error"); f["error"] != "unauthorized" {
		t.Fatalf("%v", f)
	}
	expectClose(t, c)

	phone := e.googleLogin("google-alice", "P1")
	c = e.dial("/v1/ws")
	send(t, c, obj{"t": "msg", "to": "x", "id": "1", "body": "x"})
	if f := readType(t, c, "error"); f["error"] != "unauthorized" {
		t.Fatalf("%v", f)
	}

	// No auth frame in time: closed.
	c = e.dial("/v1/ws")
	start := time.Now()
	expectClose(t, c)
	if time.Since(start) > 2*time.Second {
		t.Fatal("auth timeout not enforced")
	}
	if e.hub.Online(phone.id) {
		t.Fatal("unexpected online")
	}
}

func TestFrameSizeLimit(t *testing.T) {
	e := newEnv(t)
	phone := e.googleLogin("google-alice", "P1")
	desktop := e.pairNewDesktop(phone)
	dc, _ := e.connect(desktop.token)
	mc, _ := e.connect(phone.token)
	readType(t, dc, "presence")

	// Just under the limit is delivered.
	body := strings.Repeat("A", hub.MaxFrameBytes-200)
	send(t, mc, obj{"t": "msg", "to": desktop.id, "id": "big", "body": body})
	if f := readType(t, dc, "msg"); len(f["body"].(string)) != len(body) {
		t.Fatal("body truncated")
	}
	// Over the limit closes the connection.
	send(t, mc, obj{"t": "msg", "to": desktop.id, "id": "huge", "body": strings.Repeat("A", hub.MaxFrameBytes)})
	if code := expectClose(t, mc); code != websocket.CloseMessageTooBig {
		t.Fatalf("close code %d", code)
	}
}

func TestPingKeepsConnectionAlive(t *testing.T) {
	e := newEnv(t, envOpts{tweak: func(h *hub.Hub, _ *pairing.Service) {
		h.PingInterval = 50 * time.Millisecond
		h.ReadDeadline = 200 * time.Millisecond
	}})
	phone := e.googleLogin("google-alice", "P1")
	c := e.dialRaw("/v1/ws")
	if err := c.WriteJSON(obj{"t": "auth", "token": phone.token}); err != nil {
		t.Fatal(err)
	}
	pings := 0
	c.SetPingHandler(func(data string) error {
		pings++
		return c.WriteControl(websocket.PongMessage, []byte(data), time.Now().Add(time.Second))
	})
	// Reading processes pings and answers with pongs, so the connection
	// must survive well past the relay's read deadline.
	c.SetReadDeadline(time.Now().Add(600 * time.Millisecond))
	var ready obj
	if err := c.ReadJSON(&ready); err != nil || ready["t"] != "ready" {
		t.Fatal(ready, err)
	}
	_, _, err := c.ReadMessage()
	if ne, ok := err.(interface{ Timeout() bool }); !ok || !ne.Timeout() {
		t.Fatalf("expected a client-side timeout, got %v", err)
	}
	if pings < 3 || !e.hub.Online(phone.id) {
		t.Fatalf("pings=%d online=%v", pings, e.hub.Online(phone.id))
	}
}

func TestRevoke(t *testing.T) {
	e := newEnv(t)
	phone := e.googleLogin("google-alice", "P1")
	desktop := e.pairNewDesktop(phone)
	bob := e.googleLogin("google-bob", "Bob")
	dc, _ := e.connect(desktop.token)
	mc, _ := e.connect(phone.token)
	readType(t, dc, "presence")

	e.expectErr(403, "forbidden", "DELETE", "/v1/devices/"+desktop.id, bob.token, nil)
	e.expectErr(404, "not_found", "DELETE", "/v1/devices/no-such-device", phone.token, nil)

	e.mustDo(200, "DELETE", "/v1/devices/"+desktop.id, phone.token, nil)
	if f := read(t, dc); len(f) != 1 || f["t"] != "revoked" {
		t.Fatalf("revoked frame: %v", f)
	}
	expectClose(t, dc)
	if f := readType(t, mc, "unpaired"); f["device_id"] != desktop.id {
		t.Fatalf("%v", f)
	}
	expectSilence(t, mc, 150*time.Millisecond) // no extra offline presence

	e.expectErr(401, "unauthorized", "GET", "/v1/peers", desktop.token, nil)
	c := e.dial("/v1/ws")
	send(t, c, obj{"t": "auth", "token": desktop.token})
	readType(t, c, "error")
	if peers := e.mustDo(200, "GET", "/v1/peers", phone.token, nil)["peers"].([]any); len(peers) != 0 {
		t.Fatalf("peers after revoke: %v", peers)
	}
	send(t, mc, obj{"t": "msg", "to": desktop.id, "id": "x", "body": "x"})
	if f := readType(t, mc, "undeliverable"); f["reason"] != "not_paired" {
		t.Fatalf("%v", f)
	}

	// Self-revoke.
	e.mustDo(200, "DELETE", "/v1/devices/"+phone.id, phone.token, nil)
	readType(t, mc, "revoked")
	e.expectErr(401, "unauthorized", "GET", "/v1/peers", phone.token, nil)
}

func TestDeletePeer(t *testing.T) {
	e := newEnv(t)
	phone := e.googleLogin("google-alice", "P1")
	desktop := e.pairNewDesktop(phone)
	bob := e.googleLogin("google-bob", "Bob")
	dc, _ := e.connect(desktop.token)
	mc, _ := e.connect(phone.token)
	readType(t, dc, "presence")

	e.expectErr(404, "not_found", "DELETE", "/v1/peers/"+bob.id, desktop.token, nil)
	e.expectErr(404, "not_found", "DELETE", "/v1/peers/"+phone.id, bob.token, nil)
	e.mustDo(200, "DELETE", "/v1/peers/"+phone.id, desktop.token, nil)
	if f := readType(t, mc, "unpaired"); f["device_id"] != desktop.id {
		t.Fatalf("%v", f)
	}
	if f := readType(t, dc, "unpaired"); f["device_id"] != phone.id {
		t.Fatalf("%v", f)
	}
	e.expectErr(404, "not_found", "DELETE", "/v1/peers/"+phone.id, desktop.token, nil)
	send(t, dc, obj{"t": "msg", "to": phone.id, "id": "x", "body": "x"})
	if f := readType(t, dc, "undeliverable"); f["reason"] != "not_paired" {
		t.Fatalf("%v", f)
	}
}

func TestRateLimits(t *testing.T) {
	e := newEnv(t, envOpts{
		authLimit: api.NewLimiter(0.001, 2),
		pairLimit: api.NewLimiter(0.001, 1),
		msgAllow:  api.NewLimiter(0.001, 1).Allow,
	})
	e.devLogin("a@example.com", "p")
	e.devLogin("a@example.com", "p")
	e.expectErr(429, "rate_limited", "POST", "/v1/auth/dev", "", obj{"email": "a@example.com", "device_name": "p", "public_key": auth.RandomB64U(32)})

	e.mustDo(200, "POST", "/v1/pairings", "", obj{"public_key": auth.RandomB64U(32), "name": "L"})
	e.expectErr(429, "rate_limited", "POST", "/v1/pairings", "", obj{"public_key": auth.RandomB64U(32), "name": "L"})

	// Per-device message limit.
	e = newEnv(t, envOpts{msgAllow: api.NewLimiter(0.001, 1).Allow})
	c, _ := e.connect(e.devLogin("a@example.com", "p").token)
	send(t, c, obj{"t": "msg", "to": "a", "id": "1", "body": "x"})
	readType(t, c, "undeliverable")
	send(t, c, obj{"t": "msg", "to": "a", "id": "2", "body": "x"})
	if f := readType(t, c, "error"); f["error"] != "rate_limited" {
		t.Fatalf("%v", f)
	}
}

func doRecorder(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
	return rec
}
