package wisp

// WebSocket (RFC 6455) on the same gnet connection as HTTP: a handler calls
// Ctx.Upgrade, the 101 response goes out, and from then on the connection's
// events are frames instead of requests. Frames are parsed in place on the
// event loop, like requests; no goroutine is started per connection.

import (
	"context"
	"encoding/binary"
	"errors"
	"log"
	"runtime/debug"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/panjf2000/gnet/v2"
)

const (
	DefaultWSMaxMessageBytes  = 1 << 20
	DefaultWSMaxOutboundBytes = 4 << 20
	DefaultWSIdleTimeout      = 60 * time.Second
	DefaultWSCloseTimeout     = 5 * time.Second

	// Timeouts are checked every quarter of the shortest one, within these
	// bounds.
	maxWSTick = time.Second
	minWSTick = 10 * time.Millisecond
)

// WSMessageType is the type of a data message.
type WSMessageType byte

const (
	WSText   WSMessageType = opText
	WSBinary WSMessageType = opBinary
)

var (
	// Upgrade errors: the response (400, 403, 426 or 503) is already written.
	ErrWSHandshake   = errors.New("wisp: invalid WebSocket handshake")
	ErrWSOrigin      = errors.New("wisp: WebSocket origin not allowed")
	ErrWSUnavailable = errors.New("wisp: server shutting down")

	// ErrWSClosed is returned by Send and Close once the closing handshake
	// has started or the connection is gone.
	ErrWSClosed = errors.New("wisp: WebSocket connection closed")
	// ErrWSOutboundFull is returned by Send when the peer does not read
	// fast enough: MaxOutboundBytes are already waiting. The connection is
	// dropped.
	ErrWSOutboundFull = errors.New("wisp: WebSocket outbound limit reached")
	// ErrWSInvalidMessage is returned by Send for a type other than WSText
	// or WSBinary, or for text that is not valid UTF-8.
	ErrWSInvalidMessage = errors.New("wisp: invalid WebSocket message")
	// ErrWSInvalidClose is returned by Close for a code that cannot be sent
	// or a reason longer than 123 bytes or not valid UTF-8.
	ErrWSInvalidClose = errors.New("wisp: invalid WebSocket close code or reason")
)

// WSHandler is what a WebSocket endpoint does; one value usually serves
// every connection of the endpoint and must not change once in use.
//
// The callbacks run on the event loop, like HTTP handlers: they must not
// block. Slow work goes to a goroutine, which answers with WSConn.Send.
type WSHandler struct {
	// OnMessage is called for every complete message, fragmented or not.
	// data aliases the connection's buffers: it is valid only until
	// OnMessage returns. Send copies it, so echoing it back is fine.
	OnMessage func(ws *WSConn, typ WSMessageType, data []byte)
	// OnClose is called once when the connection is gone, with the code and
	// reason of the peer's close frame: CloseNoStatus if it had no code,
	// CloseAbnormal if the peer sent none (dropped, timed out or failed).
	OnClose func(ws *WSConn, code int, reason string)

	// AllowedOrigins lists the Origin values that may connect, such as
	// "https://example.com"; "*" allows any. When empty, only same-origin
	// requests (Origin host equal to Host) and requests without Origin,
	// which do not come from a browser, are accepted.
	AllowedOrigins []string
	// Subprotocols the server speaks, in order of preference; the first one
	// the client also offers is selected (WSConn.Subprotocol).
	Subprotocols []string

	// MaxMessageBytes limits a received message, all of its fragments
	// together (DefaultWSMaxMessageBytes if zero); larger ones close the
	// connection with 1009.
	MaxMessageBytes int
	// MaxOutboundBytes limits what may wait to be sent to a peer that does
	// not read (DefaultWSMaxOutboundBytes if zero); past it the connection
	// is dropped.
	MaxOutboundBytes int
	// IdleTimeout: after half of it without traffic from the peer a ping is
	// sent, and if nothing arrives in the other half the connection is
	// dropped (DefaultWSIdleTimeout if zero).
	IdleTimeout time.Duration
	// CloseTimeout is how long to wait for the peer's answer to a close
	// frame (DefaultWSCloseTimeout if zero).
	CloseTimeout time.Duration
}

// WSConn is a WebSocket connection. Send, Close, Context and SetContext can
// be called from any goroutine.
type WSConn struct {
	h           *WSHandler
	srv         *Server
	conn        gnet.Conn
	loop        *wsLoop
	subprotocol string
	remoteAddr  string

	maxMessage   int
	maxOutbound  int
	idleTimeout  int64 // nanoseconds
	closeTimeout int64

	// Owned by the event loop.
	need     int // bytes the frame being received needs in total
	fragOp   byte
	frag     []byte
	fragUTF8 utf8State
	// For a text frame still arriving: how much of its payload is validated
	// already, and the validator's state there.
	partialN     int
	partialState utf8State
	lastRead     int64
	pingSent     bool
	pingAt       int64
	peerClosed   bool
	peerCode     int
	peerReason   string

	mu        sync.Mutex
	out       []byte // frames waiting to be handed to gnet
	spare     []byte
	flushing  bool // the event loop flushes out when it finishes this event
	scheduled bool // a flush task is queued on the event loop
	closing   bool // a close frame is queued: no more frames
	closeAt   int64
	overflow  bool // MaxOutboundBytes exceeded: drop the connection
	closed    bool // the connection is gone
	value     any
}

// wsLoop holds the WebSocket connections of one event loop; conns is only
// touched on that loop.
type wsLoop struct {
	el    gnet.EventLoop
	conns map[*WSConn]struct{}
}

var wsEpoch = time.Now()

// monotime is a monotonic clock in nanoseconds.
func monotime() int64 {
	return int64(time.Since(wsEpoch))
}

// Upgrade switches the connection to WebSocket (RFC 6455, section 4.2):
// it validates the handshake and writes the 101 response. The handler may
// keep the WSConn, send the first messages, then return; nothing else may be
// written on c afterwards.
//
// If the handshake is not valid, Upgrade writes the error response (400;
// 426 for a request without Upgrade or with another protocol version; 403
// for an origin not allowed; 503 during Shutdown) and returns the error.
func (c *Ctx) Upgrade(h *WSHandler) (*WSConn, error) {
	if c.ws != nil {
		return nil, ErrWSHandshake
	}
	if c.srv != nil && c.srv.wsShutdown.Load() {
		c.Text(503, statusText(503))
		return nil, ErrWSUnavailable
	}
	if string(c.Method) != "GET" || string(c.req.Version) != "HTTP/1.1" {
		c.Text(400, statusText(400))
		return nil, ErrWSHandshake
	}
	if !c.headerHasToken("Upgrade", "websocket") {
		if c.Header("Upgrade") == nil {
			c.SetHeader("Upgrade", "websocket")
			c.SetHeader("Connection", "Upgrade")
			c.Text(426, statusText(426))
		} else {
			c.Text(400, statusText(400))
		}
		return nil, ErrWSHandshake
	}
	if !c.headerHasToken("Connection", "upgrade") || len(c.req.Host()) == 0 {
		c.Text(400, statusText(400))
		return nil, ErrWSHandshake
	}
	if string(c.Header("Sec-WebSocket-Version")) != "13" {
		c.SetHeader("Sec-WebSocket-Version", "13")
		c.Text(426, statusText(426))
		return nil, ErrWSHandshake
	}
	key := c.Header("Sec-WebSocket-Key")
	if !validWSKey(key) {
		c.Text(400, statusText(400))
		return nil, ErrWSHandshake
	}
	if !h.originAllowed(c.Header("Origin"), c.req.Host()) {
		c.Text(403, statusText(403))
		return nil, ErrWSOrigin
	}

	ws := &WSConn{
		h:            h,
		srv:          c.srv,
		conn:         c.conn,
		subprotocol:  h.selectSubprotocol(c),
		maxMessage:   orDefault(h.MaxMessageBytes, DefaultWSMaxMessageBytes),
		maxOutbound:  orDefault(h.MaxOutboundBytes, DefaultWSMaxOutboundBytes),
		idleTimeout:  int64(orDefault(h.IdleTimeout, DefaultWSIdleTimeout)),
		closeTimeout: int64(orDefault(h.CloseTimeout, DefaultWSCloseTimeout)),
		lastRead:     monotime(),
		// Until the event loop takes the connection over, what the handler
		// sends waits in out, behind the 101 response.
		flushing: true,
	}
	if c.conn != nil {
		ws.remoteAddr = c.conn.RemoteAddr().String()
	}

	var accept [28]byte
	wsAcceptKey(&accept, key)

	b := c.out[:c.respStart]
	b = append(b, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "...)
	b = append(b, accept[:]...)
	b = append(b, "\r\n"...)
	if ws.subprotocol != "" {
		b = append(b, "Sec-WebSocket-Protocol: "...)
		b = append(b, ws.subprotocol...)
		b = append(b, "\r\n"...)
	}
	b = append(b, c.extra...)
	b = append(b, "\r\n"...)
	c.out = b
	c.responded = true
	c.ws = ws
	return ws, nil
}

func orDefault[T int | time.Duration](v, def T) T {
	if v > 0 {
		return v
	}
	return def
}

// headerHasToken reports whether any request header called name contains
// token in its comma-separated list, ignoring ASCII case.
func (c *Ctx) headerHasToken(name, token string) bool {
	for i := range c.req.Headers {
		h := &c.req.Headers[i]
		if equalFold(h.Name, name) && hasToken(h.Value, token) {
			return true
		}
	}
	return false
}

func (h *WSHandler) originAllowed(origin, host []byte) bool {
	if len(origin) == 0 {
		return true
	}
	if len(h.AllowedOrigins) == 0 {
		// "scheme://host[:port]": compare what follows the scheme.
		for i := 0; i+2 < len(origin); i++ {
			if origin[i] == ':' && origin[i+1] == '/' && origin[i+2] == '/' {
				return equalFold(origin[i+3:], string(host))
			}
		}
		return false
	}
	for _, allowed := range h.AllowedOrigins {
		if allowed == "*" || equalFold(origin, allowed) {
			return true
		}
	}
	return false
}

func (h *WSHandler) selectSubprotocol(c *Ctx) string {
	for _, p := range h.Subprotocols {
		for i := range c.req.Headers {
			hd := &c.req.Headers[i]
			if equalFold(hd.Name, "Sec-WebSocket-Protocol") && hasExactToken(hd.Value, p) {
				return p
			}
		}
	}
	return ""
}

// hasExactToken is hasToken for case-sensitive tokens such as subprotocol
// names.
func hasExactToken(list []byte, token string) bool {
	for len(list) > 0 {
		item := list
		if i := indexByte(list, ','); i >= 0 {
			item, list = list[:i], list[i+1:]
		} else {
			list = nil
		}
		if string(trimOWS(item)) == token {
			return true
		}
	}
	return false
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

func trimOWS(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t') {
		b = b[1:]
	}
	for len(b) > 0 && (b[len(b)-1] == ' ' || b[len(b)-1] == '\t') {
		b = b[:len(b)-1]
	}
	return b
}

// Subprotocol is the subprotocol selected during the handshake, or "".
func (ws *WSConn) Subprotocol() string {
	return ws.subprotocol
}

// RemoteAddr is the peer's address.
func (ws *WSConn) RemoteAddr() string {
	return ws.remoteAddr
}

// Context returns the value set with SetContext.
func (ws *WSConn) Context() any {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	return ws.value
}

// SetContext attaches a value to the connection, such as the user it
// belongs to.
func (ws *WSConn) SetContext(v any) {
	ws.mu.Lock()
	ws.value = v
	ws.mu.Unlock()
}

// Send queues a message; data is copied, so the caller may reuse it. A nil
// error means the message is queued, not that the peer received it.
func (ws *WSConn) Send(typ WSMessageType, data []byte) error {
	if typ != WSText && typ != WSBinary || typ == WSText && !utf8.Valid(data) {
		return ErrWSInvalidMessage
	}
	return wsQueue(ws, byte(typ), data)
}

// SendText queues a text message, like Send.
func (ws *WSConn) SendText(s string) error {
	if !utf8.ValidString(s) {
		return ErrWSInvalidMessage
	}
	return wsQueue(ws, opText, s)
}

// Close starts the closing handshake (section 7.1.2): the messages already
// queued go out, then a close frame with code and reason; the connection
// ends when the peer answers, or after CloseTimeout. Messages received in
// the meantime are dropped.
func (ws *WSConn) Close(code int, reason string) error {
	if !validCloseCode(code) || len(reason) > maxControlPayload-2 || !utf8.ValidString(reason) {
		return ErrWSInvalidClose
	}
	var buf [maxControlPayload]byte
	return wsQueue(ws, opClose, appendClosePayload(buf[:0], code, reason))
}

// wsQueue appends a frame to ws.out and makes sure the event loop will
// write it.
func wsQueue[P string | []byte](ws *WSConn, op byte, payload P) error {
	ws.mu.Lock()
	if ws.closing || ws.closed {
		ws.mu.Unlock()
		return ErrWSClosed
	}
	if len(ws.out)+len(payload) > ws.maxOutbound {
		ws.overflow, ws.closing = true, true
		schedule := ws.claimFlushLocked()
		ws.mu.Unlock()
		if schedule {
			ws.scheduleFlush()
		}
		return ErrWSOutboundFull
	}
	ws.out = appendFrameHeader(ws.out, op, len(payload))
	ws.out = append(ws.out, payload...)
	if op == opClose {
		ws.closing, ws.closeAt = true, monotime()
	}
	schedule := ws.claimFlushLocked()
	ws.mu.Unlock()
	if schedule {
		ws.scheduleFlush()
	}
	return nil
}

// claimFlushLocked reports whether the caller has to queue a flush task:
// no event is flushing ws and no task is queued yet.
func (ws *WSConn) claimFlushLocked() bool {
	if ws.flushing || ws.scheduled || ws.conn == nil {
		return false
	}
	ws.scheduled = true
	return true
}

func (ws *WSConn) scheduleFlush() {
	if err := ws.conn.EventLoop().Execute(context.Background(), (*wsFlushTask)(ws)); err != nil {
		// The engine is shutting down and closes every connection anyway.
		ws.mu.Lock()
		ws.scheduled = false
		ws.mu.Unlock()
	}
}

// wsFlushTask is a WSConn as a gnet.Runnable, so queuing a flush does not
// allocate.
type wsFlushTask WSConn

func (t *wsFlushTask) Run(context.Context) error {
	ws := (*WSConn)(t)
	if !ws.flush() {
		ws.conn.Close()
	}
	return nil
}

// flush hands ws.out to gnet; it runs on the event loop. It returns false
// if the connection has to be dropped.
func (ws *WSConn) flush() bool {
	ws.mu.Lock()
	if ws.closed {
		ws.mu.Unlock()
		return true
	}
	ws.flushing, ws.scheduled = false, false
	if ws.overflow {
		ws.mu.Unlock()
		return false
	}
	out := ws.out
	ws.out, ws.spare = ws.spare, nil
	ws.mu.Unlock()

	if len(out) == 0 {
		return true
	}
	// Write copies what the socket does not take, so out can be reused.
	if _, err := ws.conn.Write(out); err != nil || ws.conn.OutboundBuffered() > ws.maxOutbound {
		return false
	}
	if cap(out) <= maxPooledBuffer {
		ws.mu.Lock()
		if ws.spare == nil {
			ws.spare = out[:0]
		}
		ws.mu.Unlock()
	}
	return true
}

// fail starts closing the connection because of the peer (section 7.1.7):
// the close frame goes out and the connection is closed right after, without
// waiting for an answer. It returns true, for process to return.
func (ws *WSConn) fail(code int, reason string) bool {
	ws.mu.Lock()
	if !ws.closing && !ws.closed {
		ws.out = appendFrameHeader(ws.out, opClose, 2+len(reason))
		ws.out = appendClosePayload(ws.out, code, reason)
		ws.closing, ws.closeAt = true, monotime()
	}
	ws.mu.Unlock()
	return true
}

// serve is process plus the recovery of a panicking callback.
func (ws *WSConn) serve(buf []byte) (consumed int, closeConn bool) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("wisp: panic in WebSocket handler for %s: %v\n%s", ws.remoteAddr, r, debug.Stack())
			closeConn = ws.fail(CloseInternalError, "")
		}
	}()
	return ws.process(buf)
}

// process handles the complete frames at the start of buf (section 5.2) and
// returns how many bytes it consumed and whether the connection has to be
// closed once the queued frames are written.
func (ws *WSConn) process(buf []byte) (consumed int, closeConn bool) {
	for {
		data := buf[consumed:]
		if len(data) < 2 {
			return consumed, false
		}
		fin, op := data[0]&0x80 != 0, data[0]&0x0F
		if data[0]&0x70 != 0 {
			// No extension is negotiated, so RSV1-3 must be zero.
			return consumed, ws.fail(CloseProtocolError, "reserved bits set")
		}
		if data[1]&0x80 == 0 {
			return consumed, ws.fail(CloseProtocolError, "frame not masked")
		}

		hdr, n := 2, uint64(data[1]&0x7F)
		switch n {
		case 126:
			if len(data) < 4 {
				return consumed, false
			}
			hdr, n = 4, uint64(binary.BigEndian.Uint16(data[2:]))
		case 127:
			if len(data) < 10 {
				return consumed, false
			}
			hdr, n = 10, binary.BigEndian.Uint64(data[2:])
		}
		hdr += 4 // masking key

		// Checked before waiting for the payload, so a frame that announces
		// gigabytes is refused at once instead of being buffered.
		switch op {
		case opText, opBinary:
			if ws.fragOp != 0 {
				return consumed, ws.fail(CloseProtocolError, "expected a continuation frame")
			}
			if n > uint64(ws.maxMessage) {
				return consumed, ws.fail(CloseMessageTooBig, "")
			}
		case opContinuation:
			if ws.fragOp == 0 {
				return consumed, ws.fail(CloseProtocolError, "unexpected continuation frame")
			}
			if n > uint64(ws.maxMessage-len(ws.frag)) {
				return consumed, ws.fail(CloseMessageTooBig, "")
			}
		case opClose, opPing, opPong:
			if !fin || n > maxControlPayload {
				return consumed, ws.fail(CloseProtocolError, "invalid control frame")
			}
		default:
			return consumed, ws.fail(CloseProtocolError, "unknown opcode")
		}

		total := hdr + int(n)
		if len(data) < total {
			if op == opText || op == opContinuation && ws.fragOp == opText {
				// Invalid UTF-8 fails the connection as soon as it arrives,
				// not when the frame is complete: come back for every chunk.
				if len(data) >= hdr && !ws.checkPartialText(op, data[hdr-4:hdr], data[hdr:]) {
					return consumed, ws.fail(CloseInvalidPayload, "invalid UTF-8")
				}
				ws.need = 0
			} else {
				ws.need = total
			}
			return consumed, false
		}
		ws.need = 0
		payload := data[hdr:total]
		unmask(payload, data[hdr-4:hdr])
		consumed += total

		switch op {
		case opText, opBinary:
			if !fin {
				ws.fragOp = op
				ws.frag = append(ws.frag[:0], payload...)
				if op == opText {
					if ws.fragUTF8 = ws.textState(utf8Accept, payload); ws.fragUTF8 == utf8Reject {
						return consumed, ws.fail(CloseInvalidPayload, "invalid UTF-8")
					}
				}
				continue
			}
			if op == opText && ws.textState(utf8Accept, payload) != utf8Accept {
				return consumed, ws.fail(CloseInvalidPayload, "invalid UTF-8")
			}
			ws.deliver(op, payload)

		case opContinuation:
			ws.frag = append(ws.frag, payload...)
			if ws.fragOp == opText {
				ws.fragUTF8 = ws.textState(ws.fragUTF8, payload)
				if ws.fragUTF8 == utf8Reject || fin && ws.fragUTF8 != utf8Accept {
					return consumed, ws.fail(CloseInvalidPayload, "invalid UTF-8")
				}
			}
			if fin {
				op := ws.fragOp
				ws.fragOp = 0
				ws.deliver(op, ws.frag)
				if cap(ws.frag) > maxPooledBuffer {
					ws.frag = nil
				} else {
					ws.frag = ws.frag[:0]
				}
			}

		case opPing:
			// Refused only once closing, when no frame may follow the close.
			_ = wsQueue(ws, opPong, payload)

		case opPong:
			// Traffic is all a pong is for: wsTraffic noted it.

		case opClose:
			code, reason, failure := parseClosePayload(payload)
			if failure != 0 {
				return consumed, ws.fail(failure, "")
			}
			ws.peerClosed, ws.peerCode, ws.peerReason = true, code, string(reason)
			// Answer with the same code (section 5.5.1), unless this is the
			// answer to our close. The server closes the TCP connection first
			// (section 7.1.1).
			var echo [2]byte
			if code == CloseNoStatus {
				_ = wsQueue(ws, opClose, echo[:0])
			} else {
				binary.BigEndian.PutUint16(echo[:], uint16(code))
				_ = wsQueue(ws, opClose, echo[:])
			}
			return consumed, true
		}
	}
}

// checkPartialText validates the part of an incomplete text frame that has
// arrived and was not validated yet. The payload is still masked, and stays
// so: it is unmasked into a scratch buffer, since the bytes Peek returns
// need not be the same memory on the next event.
func (ws *WSConn) checkPartialText(op byte, key, payload []byte) bool {
	if ws.partialN == 0 {
		ws.partialState = utf8Accept
		if op == opContinuation {
			ws.partialState = ws.fragUTF8
		}
	}
	var buf [512]byte
	for ws.partialN < len(payload) {
		n := copy(buf[:], payload[ws.partialN:])
		for i := range n {
			buf[i] ^= key[(ws.partialN+i)&3]
		}
		ws.partialN += n
		if ws.partialState = utf8Feed(ws.partialState, buf[:n]); ws.partialState == utf8Reject {
			return false
		}
	}
	return true
}

// textState returns the validator's state after the unmasked payload of a
// complete text frame, starting from state s, and skips what
// checkPartialText already validated.
func (ws *WSConn) textState(s utf8State, payload []byte) utf8State {
	if ws.partialN > 0 {
		s, payload = ws.partialState, payload[ws.partialN:]
		ws.partialN = 0
	}
	if s == utf8Accept && utf8.Valid(payload) {
		return utf8Accept
	}
	return utf8Feed(s, payload)
}

func (ws *WSConn) deliver(op byte, data []byte) {
	if ws.h.OnMessage == nil {
		return
	}
	ws.mu.Lock()
	closing := ws.closing
	ws.mu.Unlock()
	if !closing {
		ws.h.OnMessage(ws, WSMessageType(op), data)
	}
}

// discard marks a WSConn whose handshake never reached the event loop.
func (ws *WSConn) discard() {
	ws.mu.Lock()
	ws.closed, ws.out, ws.spare = true, nil, nil
	ws.mu.Unlock()
}

// wsAttach hands the upgraded connection over to the event loop.
func (s *Server) wsAttach(c gnet.Conn, ws *WSConn) {
	el := c.EventLoop()
	s.wsMu.Lock()
	l := s.wsLoops[el]
	if l == nil {
		l = &wsLoop{el: el, conns: make(map[*WSConn]struct{})}
		if s.wsLoops == nil {
			s.wsLoops = make(map[gnet.EventLoop]*wsLoop)
		}
		s.wsLoops[el] = l
	}
	s.wsMu.Unlock()

	ws.conn, ws.loop = c, l
	l.conns[ws] = struct{}{}
	s.wsActive.Add(1)
	s.lowerWSTick(min(ws.idleTimeout, ws.closeTimeout) / 4)

	// Shutdown may have looked at the loops before this one was added.
	if s.wsShutdown.Load() {
		_ = ws.Close(CloseGoingAway, "server shutting down")
	}
}

// wsDetach runs on the event loop when a WebSocket connection is gone.
func (s *Server) wsDetach(ws *WSConn) {
	ws.discard()
	delete(ws.loop.conns, ws)
	s.wsActive.Add(-1)

	if ws.h.OnClose == nil {
		return
	}
	code, reason := CloseAbnormal, ""
	if ws.peerClosed {
		code, reason = ws.peerCode, ws.peerReason
	}
	defer func() {
		if r := recover(); r != nil {
			log.Printf("wisp: panic in WebSocket OnClose for %s: %v\n%s", ws.remoteAddr, r, debug.Stack())
		}
	}()
	ws.h.OnClose(ws, code, reason)
}

// wsTraffic is OnTraffic for an upgraded connection.
func (s *Server) wsTraffic(c gnet.Conn, ws *WSConn) gnet.Action {
	ws.mu.Lock()
	ws.flushing = true
	ws.mu.Unlock()

	closeConn := false
	if n := c.InboundBuffered(); n > 0 {
		ws.lastRead, ws.pingSent = monotime(), false
		if n >= ws.need {
			buf, _ := c.Peek(-1)
			consumed, cc := ws.serve(buf)
			if consumed > 0 {
				_, _ = c.Discard(consumed)
			}
			closeConn = cc
		}
	}
	if !ws.flush() || closeConn {
		return gnet.Close
	}
	return gnet.None
}

func (s *Server) lowerWSTick(d int64) {
	d = max(d, int64(minWSTick))
	for {
		cur := s.wsTick.Load()
		if cur != 0 && cur <= d || s.wsTick.CompareAndSwap(cur, d) {
			return
		}
	}
}

func (s *Server) wsTickInterval() time.Duration {
	if d := time.Duration(s.wsTick.Load()); d > 0 && d < maxWSTick {
		return d
	}
	return maxWSTick
}

// wsSweep queues the timeout checks on every event loop that has
// WebSocket connections; it runs on gnet's ticker goroutine.
func (s *Server) wsSweep() {
	s.wsMu.Lock()
	defer s.wsMu.Unlock()
	for el, l := range s.wsLoops {
		_ = el.Execute(context.Background(), l)
	}
}

// Run checks the timeouts of the loop's connections, on the loop.
func (l *wsLoop) Run(context.Context) error {
	now := monotime()
	for ws := range l.conns {
		ws.mu.Lock()
		closing, closeAt := ws.closing, ws.closeAt
		ws.mu.Unlock()

		// A peer is dropped only if a ping went unanswered, however late
		// the first check comes.
		switch {
		case closing && now-closeAt > ws.closeTimeout:
			ws.conn.Close()
		case ws.pingSent && now-ws.pingAt > ws.idleTimeout/2:
			ws.conn.Close()
		case !closing && !ws.pingSent && now-ws.lastRead > ws.idleTimeout/2:
			ws.pingSent, ws.pingAt = true, now
			_ = wsQueue(ws, opPing, "")
		}
	}
	return nil
}

// wsShutdownAll starts the closing handshake on every WebSocket connection
// and waits for them to be gone, or for ctx to expire.
func (s *Server) wsShutdownAll(ctx context.Context) {
	s.wsShutdown.Store(true)

	s.wsMu.Lock()
	for el, l := range s.wsLoops {
		_ = el.Execute(ctx, gnet.RunnableFunc(func(context.Context) error {
			for ws := range l.conns {
				_ = ws.Close(CloseGoingAway, "server shutting down")
			}
			return nil
		}))
	}
	s.wsMu.Unlock()

	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for s.wsActive.Load() > 0 {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
