package api_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/mohammadirham37/jenderalcode_backend/internal/api"
	"github.com/mohammadirham37/jenderalcode_backend/internal/auth"
	"github.com/mohammadirham37/jenderalcode_backend/internal/hub"
	"github.com/mohammadirham37/jenderalcode_backend/internal/pairing"
	"github.com/mohammadirham37/jenderalcode_backend/internal/store"
)

type env struct {
	t   *testing.T
	srv *httptest.Server
	st  *store.Store
	hub *hub.Hub
	ps  *pairing.Service
}

type envOpts struct {
	authLimit, pairLimit *api.Limiter
	msgAllow             func(string) bool
	tweak                func(*hub.Hub, *pairing.Service)
}

var fakeGoogle = auth.FakeVerifier{
	"google-alice":  {Subject: "sub-alice", Email: "alice@example.com", Name: "Alice"},
	"google-alice2": {Subject: "sub-alice", Email: "alice@example.com", Name: "Alice"},
	"google-bob":    {Subject: "sub-bob", Email: "bob@example.com", Name: "Bob"},
}

func newEnv(t *testing.T, o ...envOpts) *env {
	t.Helper()
	var opts envOpts
	if len(o) > 0 {
		opts = o[0]
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := hub.New(st, log, opts.msgAllow)
	ps := pairing.New(st, h, log)
	if opts.tweak != nil {
		opts.tweak(h, ps)
	}
	srv := httptest.NewServer(api.NewRouter(api.Deps{
		Store: st, Hub: h, Pairing: ps, Verifier: fakeGoogle, DevLogin: true, Log: log,
		AuthLimit: opts.authLimit, PairLimit: opts.pairLimit,
	}))
	t.Cleanup(func() {
		h.CloseAll()
		ps.CloseAll()
		if !h.Wait(5*time.Second) || !ps.Wait(5*time.Second) {
			t.Error("websocket handlers did not stop")
		}
		srv.Close()
		st.Close()
	})
	return &env{t: t, srv: srv, st: st, hub: h, ps: ps}
}

type obj = map[string]any

func (e *env) do(method, path, token string, body any) (int, obj) {
	e.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		rd = bytes.NewReader(b)
	default:
		js, _ := json.Marshal(b)
		rd = bytes.NewReader(js)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out obj
	json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func (e *env) mustDo(status int, method, path, token string, body any) obj {
	e.t.Helper()
	got, out := e.do(method, path, token, body)
	if got != status {
		e.t.Fatalf("%s %s: status %d, want %d, body %v", method, path, got, status, out)
	}
	return out
}

func (e *env) expectErr(status int, code, method, path, token string, body any) {
	e.t.Helper()
	out := e.mustDo(status, method, path, token, body)
	if out["error"] != code || out["message"] == nil {
		e.t.Fatalf("%s %s: error %v, want %q", method, path, out, code)
	}
}

type dev struct {
	id, token, pk string
}

func (e *env) googleLogin(idToken, name string) dev {
	e.t.Helper()
	pk := auth.RandomB64U(32)
	out := e.mustDo(200, "POST", "/v1/auth/google", "", obj{"id_token": idToken, "device_name": name, "public_key": pk})
	return dev{out["device_id"].(string), out["device_token"].(string), pk}
}

func (e *env) devLogin(email, name string) dev {
	e.t.Helper()
	pk := auth.RandomB64U(32)
	out := e.mustDo(200, "POST", "/v1/auth/dev", "", obj{"email": email, "device_name": name, "public_key": pk})
	return dev{out["device_id"].(string), out["device_token"].(string), pk}
}

// wsConn reads frames in the background so tests can wait for "no frame"
// without breaking the connection (gorilla connections are unusable after a
// read timeout).
type wsConn struct {
	*websocket.Conn
	frames chan obj
	err    error // set before frames is closed
}

func (e *env) dialRaw(path string) *websocket.Conn {
	e.t.Helper()
	u := "ws" + strings.TrimPrefix(e.srv.URL, "http") + path
	c, _, err := websocket.DefaultDialer.Dial(u, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { c.Close() })
	return c
}

func (e *env) dial(path string) *wsConn {
	e.t.Helper()
	w := &wsConn{Conn: e.dialRaw(path), frames: make(chan obj, 64)}
	go func() {
		defer close(w.frames)
		for {
			var f obj
			if err := w.ReadJSON(&f); err != nil {
				w.err = err
				return
			}
			w.frames <- f
		}
	}()
	return w
}

func send(t *testing.T, c *wsConn, v any) {
	t.Helper()
	if err := c.WriteJSON(v); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, c *wsConn) obj {
	t.Helper()
	select {
	case f, ok := <-c.frames:
		if !ok {
			t.Fatalf("connection closed: %v", c.err)
		}
		return f
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for a frame")
	}
	return nil
}

func readType(t *testing.T, c *wsConn, typ string) obj {
	t.Helper()
	f := read(t, c)
	if f["t"] != typ {
		t.Fatalf("got frame %v, want t=%q", f, typ)
	}
	return f
}

// expectClose waits for the connection to close (frames before it are
// discarded) and returns the close code, or -1 for a non-close error.
func expectClose(t *testing.T, c *wsConn) int {
	t.Helper()
	timeout := time.After(3 * time.Second)
	for {
		select {
		case _, ok := <-c.frames:
			if ok {
				continue
			}
			var ce *websocket.CloseError
			if errors.As(c.err, &ce) {
				return ce.Code
			}
			return -1
		case <-timeout:
			t.Fatal("connection not closed")
		}
	}
}

func expectSilence(t *testing.T, c *wsConn, d time.Duration) {
	t.Helper()
	select {
	case f, ok := <-c.frames:
		if ok {
			t.Fatalf("unexpected frame %v", f)
		}
	case <-time.After(d):
	}
}

// connect opens /v1/ws, authenticates and returns the ready frame.
func (e *env) connect(token string) (*wsConn, obj) {
	e.t.Helper()
	c := e.dial("/v1/ws")
	send(e.t, c, obj{"t": "auth", "token": token})
	return c, readType(e.t, c, "ready")
}

func (e *env) waitFor(cond func() bool) {
	e.t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			e.t.Fatal("condition not met")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// startPairing creates a pairing (with an optional desktop token) and opens
// the authenticated wait socket.
func (e *env) startPairing(desktopToken, pk, name string) (obj, *wsConn) {
	e.t.Helper()
	p := e.mustDo(200, "POST", "/v1/pairings", desktopToken, obj{"public_key": pk, "name": name})
	w := e.dial("/v1/pairings/" + p["pairing_id"].(string) + "/wait")
	send(e.t, w, obj{"t": "auth", "secret": p["wait_secret"]})
	id := p["pairing_id"].(string)
	e.waitFor(func() bool { return e.ps.IsWaiting(id) })
	return p, w
}

// pairNewDesktop pairs a brand-new desktop with the phone and returns it.
func (e *env) pairNewDesktop(phone dev) dev {
	e.t.Helper()
	pk := auth.RandomB64U(32)
	p, w := e.startPairing("", pk, "Laptop")
	e.mustDo(200, "POST", "/v1/pairings/claim", phone.token, obj{"code": p["code"]})
	e.mustDo(200, "POST", "/v1/pairings/"+p["pairing_id"].(string)+"/approve", phone.token, obj{})
	a := readType(e.t, w, "approved")
	return dev{a["device_id"].(string), a["device_token"].(string), pk}
}
