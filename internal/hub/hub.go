// Package hub holds the live /v1/ws connections (docs/protocol.md §5.1) and
// routes opaque, end-to-end-encrypted message bodies between paired,
// non-revoked devices. It never inspects or logs bodies.
package hub

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/mohammadirham37/jenderalcode_backend/internal/auth"
	"github.com/mohammadirham37/jenderalcode_backend/internal/store"
)

// Protocol limits (§5).
const (
	MaxFrameBytes = 1 << 20
	PingInterval  = 30 * time.Second
	ReadDeadline  = 75 * time.Second
	AuthTimeout   = 10 * time.Second
	WriteWait     = 10 * time.Second

	// CloseReplaced closes an older connection when the same device connects again.
	CloseReplaced = 4000

	sendBuffer   = 256
	maxIDLen     = 128
	storeTimeout = 5 * time.Second
)

// Upgrader is shared by both WebSocket endpoints. Origin is not checked:
// clients are native apps, authentication is a token in the first frame
// (never a cookie or URL), so cross-site WebSocket hijacking gains nothing.
var Upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin:     func(*http.Request) bool { return true },
}

// Store is what the hub needs from persistence.
type Store interface {
	auth.DeviceLookup
	Peers(ctx context.Context, deviceID string) ([]store.Device, error)
	IsPaired(ctx context.Context, a, b string) (bool, error)
	TouchLastSeen(ctx context.Context, id string, now int64) error
}

// Hub tracks one connection per device.
type Hub struct {
	store Store
	log   *slog.Logger
	allow func(deviceID string) bool // per-device message rate limit

	// Timings; tests may shorten them.
	PingInterval time.Duration
	ReadDeadline time.Duration
	AuthTimeout  time.Duration

	mu      sync.Mutex
	clients map[string]*client
	wg      sync.WaitGroup // live ServeWS handlers
}

// New creates a hub. allow may be nil (no rate limit).
func New(st Store, log *slog.Logger, allow func(string) bool) *Hub {
	if allow == nil {
		allow = func(string) bool { return true }
	}
	return &Hub{
		store: st, log: log, allow: allow,
		PingInterval: PingInterval, ReadDeadline: ReadDeadline, AuthTimeout: AuthTimeout,
		clients: map[string]*client{},
	}
}

type client struct {
	deviceID string
	conn     *websocket.Conn
	send     chan []byte
	done     chan struct{}
	once     sync.Once
	code     int
	reason   string
}

func (c *client) enqueue(b []byte) bool {
	select {
	case <-c.done:
		return false
	default:
	}
	select {
	case c.send <- b:
		return true
	default:
		return false
	}
}

// close asks the writer to flush queued frames, send a close frame and drop
// the connection.
func (c *client) close(code int, reason string) {
	c.once.Do(func() {
		c.code, c.reason = code, reason
		close(c.done)
	})
}

func (c *client) writePump(ping time.Duration) {
	t := time.NewTicker(ping)
	defer t.Stop()
	defer c.conn.Close()
	write := func(b []byte) error {
		c.conn.SetWriteDeadline(time.Now().Add(WriteWait))
		return c.conn.WriteMessage(websocket.TextMessage, b)
	}
	for {
		select {
		case b := <-c.send:
			if err := write(b); err != nil {
				c.close(websocket.CloseAbnormalClosure, "")
				return
			}
		case <-t.C:
			if err := c.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(WriteWait)); err != nil {
				c.close(websocket.CloseAbnormalClosure, "")
				return
			}
		case <-c.done:
		drain:
			for {
				select {
				case b := <-c.send:
					if write(b) != nil {
						return
					}
				default:
					break drain
				}
			}
			c.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(c.code, c.reason), time.Now().Add(WriteWait))
			return
		}
	}
}

// Frames (§5.1).
type inFrame struct {
	T     string `json:"t"`
	Token string `json:"token"`
	To    string `json:"to"`
	ID    string `json:"id"`
	Body  string `json:"body"`
}

type peerPresence struct {
	DeviceID string `json:"device_id"`
	Online   bool   `json:"online"`
}

type readyFrame struct {
	T        string         `json:"t"`
	DeviceID string         `json:"device_id"`
	Peers    []peerPresence `json:"peers"`
}

type msgFrame struct {
	T    string `json:"t"`
	From string `json:"from"`
	ID   string `json:"id"`
	Body string `json:"body"`
}

type undeliverableFrame struct {
	T      string `json:"t"`
	ID     string `json:"id"`
	To     string `json:"to"`
	Reason string `json:"reason"`
}

type presenceFrame struct {
	T        string `json:"t"`
	DeviceID string `json:"device_id"`
	Online   bool   `json:"online"`
}

type deviceFrame struct {
	T        string `json:"t"`
	DeviceID string `json:"device_id"`
}

type errorFrame struct {
	T     string `json:"t"`
	Error string `json:"error"`
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// ErrorFrame encodes {"t":"error","error":code}.
func ErrorFrame(code string) []byte { return mustJSON(errorFrame{T: "error", Error: code}) }

// RejectAndClose writes an error frame and a policy-violation close, then
// closes conn. Used for failed auth on both WebSocket endpoints.
func RejectAndClose(conn *websocket.Conn, code string) {
	conn.SetWriteDeadline(time.Now().Add(WriteWait))
	conn.WriteMessage(websocket.TextMessage, ErrorFrame(code))
	conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, code), time.Now().Add(WriteWait))
	conn.Close()
}

func (h *Hub) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), storeTimeout)
}

// ServeWS handles GET /v1/ws.
func (h *Hub) ServeWS(w http.ResponseWriter, r *http.Request) {
	conn, err := Upgrader.Upgrade(w, r, nil)
	if err != nil {
		return // Upgrade already replied
	}
	h.wg.Add(1)
	defer h.wg.Done()
	conn.SetReadLimit(MaxFrameBytes)
	conn.SetReadDeadline(time.Now().Add(h.AuthTimeout))
	_, data, err := conn.ReadMessage()
	if err != nil {
		conn.Close()
		return
	}
	var f inFrame
	if json.Unmarshal(data, &f) != nil || f.T != "auth" || f.Token == "" {
		RejectAndClose(conn, "unauthorized")
		return
	}
	ctx, cancel := h.ctx()
	dev, err := auth.Authenticate(ctx, h.store, f.Token)
	cancel()
	if err != nil {
		RejectAndClose(conn, "unauthorized")
		return
	}

	c := &client{deviceID: dev.ID, conn: conn, send: make(chan []byte, sendBuffer), done: make(chan struct{})}
	h.mu.Lock()
	old := h.clients[dev.ID]
	h.clients[dev.ID] = c
	h.mu.Unlock()
	if old != nil {
		old.close(CloseReplaced, "replaced")
		h.log.Info("ws replaced", "device_id", dev.ID)
	}
	go c.writePump(h.PingInterval)

	peers := h.peerIDs(dev.ID)
	ready := readyFrame{T: "ready", DeviceID: dev.ID, Peers: make([]peerPresence, 0, len(peers))}
	for _, p := range peers {
		ready.Peers = append(ready.Peers, peerPresence{DeviceID: p, Online: h.Online(p)})
	}
	c.enqueue(mustJSON(ready))
	h.touch(dev.ID)
	for _, p := range peers {
		h.sendTo(p, mustJSON(presenceFrame{T: "presence", DeviceID: dev.ID, Online: true}))
	}
	h.log.Info("ws connected", "device_id", dev.ID, "kind", dev.Kind)

	h.readLoop(c)

	c.close(websocket.CloseNormalClosure, "")
	h.mu.Lock()
	current := h.clients[dev.ID] == c
	if current {
		delete(h.clients, dev.ID)
	}
	h.mu.Unlock()
	if current {
		h.touch(dev.ID)
		for _, p := range h.peerIDs(dev.ID) {
			h.sendTo(p, mustJSON(presenceFrame{T: "presence", DeviceID: dev.ID, Online: false}))
		}
	}
	h.log.Info("ws disconnected", "device_id", dev.ID)
}

func (h *Hub) readLoop(c *client) {
	extend := func() { c.conn.SetReadDeadline(time.Now().Add(h.ReadDeadline)) }
	extend()
	c.conn.SetPongHandler(func(string) error { extend(); return nil })
	for {
		_, data, err := c.conn.ReadMessage()
		if err != nil {
			return
		}
		extend()
		var f inFrame
		if json.Unmarshal(data, &f) != nil {
			c.enqueue(ErrorFrame("bad_request"))
			continue
		}
		switch f.T {
		case "msg":
			h.route(c, f)
		default:
			// Unknown frame types are ignored for forward compatibility.
		}
	}
}

func (h *Hub) route(c *client, f inFrame) {
	if f.To == "" || f.ID == "" || f.Body == "" || len(f.To) > maxIDLen || len(f.ID) > maxIDLen {
		c.enqueue(ErrorFrame("bad_request"))
		return
	}
	if !h.allow(c.deviceID) {
		c.enqueue(ErrorFrame("rate_limited"))
		return
	}
	undeliverable := func(reason string) {
		c.enqueue(mustJSON(undeliverableFrame{T: "undeliverable", ID: f.ID, To: f.To, Reason: reason}))
	}
	paired := false
	if f.To != c.deviceID {
		ctx, cancel := h.ctx()
		var err error
		paired, err = h.store.IsPaired(ctx, c.deviceID, f.To)
		cancel()
		if err != nil {
			h.log.Error("pair lookup failed", "device_id", c.deviceID, "err", err)
			undeliverable("offline")
			return
		}
	}
	if !paired {
		undeliverable("not_paired")
		return
	}
	if !h.sendTo(f.To, mustJSON(msgFrame{T: "msg", From: c.deviceID, ID: f.ID, Body: f.Body})) {
		undeliverable("offline")
	}
}

func (h *Hub) get(id string) *client {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.clients[id]
}

func (h *Hub) sendTo(id string, frame []byte) bool {
	c := h.get(id)
	return c != nil && c.enqueue(frame)
}

func (h *Hub) peerIDs(id string) []string {
	ctx, cancel := h.ctx()
	defer cancel()
	peers, err := h.store.Peers(ctx, id)
	if err != nil {
		h.log.Error("peer lookup failed", "device_id", id, "err", err)
		return nil
	}
	ids := make([]string, len(peers))
	for i, p := range peers {
		ids[i] = p.ID
	}
	return ids
}

func (h *Hub) touch(id string) {
	ctx, cancel := h.ctx()
	defer cancel()
	if err := h.store.TouchLastSeen(ctx, id, time.Now().UnixMilli()); err != nil {
		h.log.Warn("last_seen update failed", "device_id", id, "err", err)
	}
}

// Online reports whether the device has a live connection.
func (h *Hub) Online(id string) bool { return h.get(id) != nil }

// Paired tells two newly paired devices about each other's presence when
// both are connected.
func (h *Hub) Paired(a, b string) {
	if h.Online(a) && h.Online(b) {
		h.sendTo(a, mustJSON(presenceFrame{T: "presence", DeviceID: b, Online: true}))
		h.sendTo(b, mustJSON(presenceFrame{T: "presence", DeviceID: a, Online: true}))
	}
}

// Unpaired notifies both former peers that their pair was removed.
func (h *Hub) Unpaired(a, b string) {
	h.sendTo(a, mustJSON(deviceFrame{T: "unpaired", DeviceID: b}))
	h.sendTo(b, mustJSON(deviceFrame{T: "unpaired", DeviceID: a}))
}

// Revoked sends {"t":"revoked"} to the device and closes it, then tells its
// former peers with `unpaired`.
func (h *Hub) Revoked(id string, formerPeers []string) {
	h.mu.Lock()
	c := h.clients[id]
	delete(h.clients, id)
	h.mu.Unlock()
	if c != nil {
		c.enqueue([]byte(`{"t":"revoked"}`))
		c.close(websocket.CloseNormalClosure, "revoked")
	}
	for _, p := range formerPeers {
		h.sendTo(p, mustJSON(deviceFrame{T: "unpaired", DeviceID: id}))
	}
}

// Kick closes the device's connection with CloseReplaced (used when its
// token is rotated by a new login).
func (h *Hub) Kick(id string) {
	if c := h.get(id); c != nil {
		c.close(CloseReplaced, "replaced")
	}
}

// CloseAll closes every connection (graceful shutdown).
func (h *Hub) CloseAll() {
	h.mu.Lock()
	cs := make([]*client, 0, len(h.clients))
	for _, c := range h.clients {
		cs = append(cs, c)
	}
	h.mu.Unlock()
	for _, c := range cs {
		c.close(websocket.CloseGoingAway, "shutdown")
	}
}

// Wait blocks until all WebSocket handlers have returned or the timeout
// passes; it reports whether they all returned.
func (h *Hub) Wait(timeout time.Duration) bool { return WaitGroupTimeout(&h.wg, timeout) }

// WaitGroupTimeout waits for wg up to timeout.
func WaitGroupTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}
