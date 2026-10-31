// Package wisp is a small HTTP/1.1 server on top of gnet: requests are parsed
// in place with the embedded wildcat parser and dispatched by a Router.
// A handler can switch its connection to WebSocket (RFC 6455) with
// Ctx.Upgrade: the same connection then carries frames (websocket.go).
//
// Handlers run on gnet's event loops, so a handler that blocks stalls every
// connection of its loop: a slow handler calls Ctx.Async, which runs the rest
// of its work on a goroutine pool and sends the response from there.
//
// gnet has no TLS: ListenAndServeTLS serves HTTPS with crypto/tls on
// goroutines of its own instead (tls.go), running the same HTTP and
// WebSocket code.
//
// Not supported: HTTP/2, transfer codings other than chunked, chunked bodies
// larger than MaxBodyBytes (only Content-Length bodies can be streamed).
package wisp

import (
	"bytes"
	"context"
	"errors"
	"log"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/panjf2000/gnet/v2"

	"github.com/panzarasa/wisp/wildcat"
)

const (
	DefaultMaxHeaderBytes   = 64 << 10
	DefaultMaxBodyBytes     = 4 << 20
	DefaultMaxOutboundBytes = 4 << 20

	DefaultReadHeaderTimeout = 10 * time.Second
	DefaultReadTimeout       = 60 * time.Second
	DefaultWriteTimeout      = 30 * time.Second
	DefaultIdleTimeout       = 60 * time.Second

	DefaultMaxAsync = 10000

	// Response buffers that grew beyond this are not kept for reuse.
	maxPooledBuffer = 64 << 10
)

// Server serves HTTP/1.1 over gnet (ListenAndServe) and over TLS
// (ListenAndServeTLS). The zero value needs only a Handler; the other fields
// must not change once it serves.
type Server struct {
	Handler Handler

	// StreamHandler handles the requests whose Content-Length exceeds
	// MaxBodyBytes, before their body arrives: to receive the body piece by
	// piece it calls Ctx.ReceiveBody, otherwise its response is sent and the
	// connection closed. Without a StreamHandler such requests get a 413.
	StreamHandler Handler

	// MaxHeaderBytes limits the request line plus headers
	// (DefaultMaxHeaderBytes if zero); larger requests get a 431.
	MaxHeaderBytes int
	// MaxBodyBytes limits a request body, which is buffered whole before
	// the handler runs (DefaultMaxBodyBytes if zero); larger requests get a
	// 413, or go to StreamHandler.
	MaxBodyBytes int
	// MaxOutboundBytes bounds the responses waiting for a client to read
	// them (DefaultMaxOutboundBytes if zero): past it, the requests the
	// client pipelines stay unread until it catches up.
	MaxOutboundBytes int

	// Timeouts: zero means the default, a negative value none.
	//
	// ReadHeaderTimeout is how long a request may take from its first byte
	// to the end of its header, and a TLS handshake to complete
	// (DefaultReadHeaderTimeout).
	ReadHeaderTimeout time.Duration
	// ReadTimeout is how long a request may take from its first byte to the
	// end of its body (DefaultReadTimeout); for a body passed to a
	// BodyStream, the longest pause between two pieces.
	ReadTimeout time.Duration
	// WriteTimeout is how long responses may wait for a client that does
	// not read them (DefaultWriteTimeout).
	WriteTimeout time.Duration
	// IdleTimeout is how long a keep-alive connection may wait for its next
	// request (DefaultIdleTimeout).
	IdleTimeout time.Duration

	// MaxAsync limits the handlers running at the same time with Ctx.Async
	// (DefaultMaxAsync if zero); past it the requests get a 503.
	MaxAsync int

	// TLSAcceptLoops is the number of goroutines accepting TLS connections
	// (GOMAXPROCS, at most 8, if zero).
	TLSAcceptLoops int

	engine  atomic.Pointer[gnet.Engine]
	started atomic.Bool
	pool    sync.Pool

	mu        sync.Mutex
	loops     map[any]*loop
	listeners map[*tlsListener]struct{}

	// The timeout checks (transport.go).
	tick      atomic.Int64 // nanoseconds between two checks
	retick    chan struct{}
	stopSweep chan struct{}
	sweepOnce sync.Once
	stopOnce  sync.Once

	async workerPool // Ctx.Async
	conns workerPool // TLS connections

	httpActive atomic.Int64
	wsActive   atomic.Int64
	shutdown   atomic.Bool
}

// connState is what an HTTP connection keeps between events; it is only
// touched on the connection's loop.
type connState struct {
	parser *wildcat.HTTPParser
	ctx    Ctx
	t      transport
	loop   *loop

	// When a request is only partially buffered: the bytes it needs in
	// total, so the events that bring the rest of a large body do not
	// re-parse it.
	need int
	// A "100 Continue" was already sent for the request being buffered.
	continued bool
	// The chunked body being buffered.
	chunk chunkScan
	// The body being passed to a BodyStream, and how much of it is left.
	stream     *BodyStream
	streamLeft int64

	// Timeouts, in monotime.
	reqStart   int64 // first byte of the request being received; 0 if none
	headerDone bool  // the header of that request is complete
	lastActive int64 // last request served
	blocked    bool  // MaxOutboundBytes reached: the next requests wait
	blockedAt  int64

	// A handler answers from a goroutine (Ctx.Async): the next requests
	// wait.
	async bool
	// The connection is gone while async: the state is not reused.
	dead bool
}

// ListenAndServe serves on addr (":8080" or a gnet address such as
// "tcp://127.0.0.1:8080") until Shutdown is called or gnet fails.
func (s *Server) ListenAndServe(addr string, opts ...gnet.Option) error {
	if s.Handler == nil {
		return errors.New("wisp: Server.Handler is nil")
	}
	if !strings.Contains(addr, "://") {
		addr = "tcp://" + addr
	}
	s.started.Store(true)
	s.startSweeper()
	return gnet.Run(&eventHandler{s: s}, addr, opts...)
}

// Shutdown stops the server gracefully: no new connection is accepted, idle
// HTTP connections are closed, and the others once their current request
// is answered (with "Connection: close"); WebSocket connections are sent a
// 1001 "going away" close frame. When they are all gone, or ctx expires,
// what is left is closed and ListenAndServe and ListenAndServeTLS return.
// It returns ctx.Err() if ctx expired first. A Server cannot serve again
// after Shutdown.
func (s *Server) Shutdown(ctx context.Context) error {
	if !s.started.Load() {
		return errors.New("wisp: server is not running")
	}
	s.shutdown.Store(true)

	s.mu.Lock()
	for ln := range s.listeners {
		_ = ln.Close()
	}
	s.mu.Unlock()

	// Idle connections are closed by the timeout checks, from now on
	// frequent.
	s.lowerTick(int64(50 * time.Millisecond))
	s.wsCloseAll()
	s.eachLoop(func(l *loop) gnet.Runnable { return l })

	err := s.waitIdle(ctx)

	if eng := s.engine.Load(); eng != nil {
		// Stop stops the engine even when ctx has already expired.
		if stopErr := eng.Stop(ctx); err == nil {
			err = stopErr
		}
	}
	s.closeTLSConns()
	s.stopOnce.Do(func() {
		if s.stopSweep != nil {
			close(s.stopSweep)
		}
	})
	return err
}

// waitIdle waits for every connection to be gone, or ctx to expire.
func (s *Server) waitIdle(ctx context.Context) error {
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for s.httpActive.Load()+s.wsActive.Load() > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
	return nil
}

func (s *Server) maxHeaderBytes() int {
	return orDefault(s.MaxHeaderBytes, DefaultMaxHeaderBytes)
}

func (s *Server) maxBodyBytes() int {
	return orDefault(s.MaxBodyBytes, DefaultMaxBodyBytes)
}

func (s *Server) maxOutboundBytes() int {
	return orDefault(s.MaxOutboundBytes, DefaultMaxOutboundBytes)
}

// maxInbound bounds the requests that may wait, unread, while a connection
// is blocked or async.
func (s *Server) maxInbound() int {
	return s.maxHeaderBytes() + s.maxBodyBytes()
}

func (s *Server) maxAsync() int {
	return orDefault(s.MaxAsync, DefaultMaxAsync)
}

// timeout returns d, or def if d is zero, in nanoseconds; 0 if d is
// negative.
func timeout(d, def time.Duration) int64 {
	switch {
	case d < 0:
		return 0
	case d == 0:
		return int64(def)
	}
	return int64(d)
}

func (s *Server) readHeaderTimeout() int64 {
	return timeout(s.ReadHeaderTimeout, DefaultReadHeaderTimeout)
}

func (s *Server) readTimeout() int64 { return timeout(s.ReadTimeout, DefaultReadTimeout) }

func (s *Server) writeTimeout() int64 { return timeout(s.WriteTimeout, DefaultWriteTimeout) }

func (s *Server) idleTimeout() int64 { return timeout(s.IdleTimeout, DefaultIdleTimeout) }

func (s *Server) getState() *connState {
	if st, ok := s.pool.Get().(*connState); ok {
		return st
	}
	return &connState{parser: wildcat.NewHTTPParser()}
}

func (s *Server) putState(st *connState) {
	c := &st.ctx
	out, extra, pathBuf := c.out[:0], c.extra[:0], c.pathBuf[:0]
	if cap(out) > maxPooledBuffer {
		out = nil
	}
	query, form := c.query, c.form
	query.reset()
	form.reset()
	// Drop every reference into the connection's buffers.
	*st = connState{
		parser: st.parser,
		ctx:    Ctx{out: out, extra: extra, pathBuf: pathBuf, query: query, form: form},
	}
	s.pool.Put(st)
}

// openHTTP starts serving a new connection.
func (s *Server) openHTTP(t transport, l *loop) {
	st := s.getState()
	st.t, st.loop = t, l
	st.lastActive = monotime()
	t.SetContext(st)
	l.http[st] = struct{}{}
	s.httpActive.Add(1)
}

// closed runs on the loop when a connection is gone.
func (s *Server) closed(state any) {
	switch st := state.(type) {
	case *connState:
		delete(st.loop.http, st)
		s.httpActive.Add(-1)
		if st.async {
			// The goroutine still holds the state: it must not be reused.
			st.dead = true
		} else {
			s.putState(st)
		}
	case *WSConn:
		s.wsDetach(st)
	}
}

// traffic handles what arrived on a connection, on its loop. It returns
// true if the connection must be closed once what is queued is written.
func (s *Server) traffic(state any) bool {
	switch st := state.(type) {
	case *connState:
		return s.httpTraffic(st)
	case *WSConn:
		return s.wsTraffic(st)
	}
	return true
}

type eventHandler struct {
	gnet.BuiltinEventEngine
	s *Server
}

func (h *eventHandler) OnBoot(eng gnet.Engine) gnet.Action {
	h.s.engine.Store(&eng)
	return gnet.None
}

func (h *eventHandler) OnOpen(c gnet.Conn) ([]byte, gnet.Action) {
	if h.s.shutdown.Load() {
		return nil, gnet.Close
	}
	h.s.openHTTP(&gnetConn{c}, h.s.gnetLoop(c.EventLoop()))
	return nil, gnet.None
}

func (h *eventHandler) OnClose(c gnet.Conn, _ error) gnet.Action {
	h.s.closed(c.Context())
	c.SetContext(nil)
	return gnet.None
}

func (h *eventHandler) OnTraffic(c gnet.Conn) gnet.Action {
	if h.s.traffic(c.Context()) {
		return gnet.Close
	}
	return gnet.None
}

// httpTraffic handles what arrived on an HTTP connection.
func (s *Server) httpTraffic(st *connState) bool {
	t := st.t
	if st.async || st.blocked && t.OutboundBuffered() > s.maxOutboundBytes() {
		// The requests wait, unread, for the handler to answer or the
		// client to read: bound what may pile up meanwhile.
		return t.InboundBuffered() > s.maxInbound()
	}
	st.blocked = false

	if st.need > 0 {
		if t.InboundBuffered() < st.need {
			return false
		}
		st.need = 0
	}

	c := &st.ctx
	for {
		// Peek, not Next: an incomplete request stays buffered and is seen
		// again, followed by the new bytes, on the next event.
		buf, _ := t.Peek(-1)

		c.out, c.respStart = c.out[:0], 0
		c.conn = t
		consumed, closeConn := s.serve(st, buf)
		ws := c.ws

		// Discard(0) would drop the whole buffer.
		if consumed > 0 {
			_, _ = t.Discard(consumed)
		}
		if len(c.out) > 0 {
			// Write copies what the socket does not take, so out can be
			// reused.
			if _, err := t.Write(c.out); err != nil {
				closeConn = true
			}
		}
		if closeConn {
			if ws != nil {
				ws.discard()
			}
			return true
		}
		if ws != nil {
			return s.upgraded(st, ws)
		}

		now := monotime()
		if consumed > 0 {
			st.lastActive = now
		}
		if consumed < len(buf) || st.stream != nil {
			// A request is on its way: the read timeouts run from its
			// first byte, or for a streamed body from its last piece.
			if st.reqStart == 0 || consumed > 0 {
				st.reqStart = now
			}
		} else {
			st.reqStart, st.headerDone = 0, false
		}

		if !st.blocked {
			return false
		}
		if t.OutboundBuffered() > s.maxOutboundBytes() {
			st.blockedAt = now
			return false
		}
		// The socket took the responses: go on with the next requests.
		st.blocked = false
	}
}

// upgraded hands a connection whose handler called Upgrade over to
// WebSocket.
func (s *Server) upgraded(st *connState, ws *WSConn) bool {
	t, l := st.t, st.loop
	delete(l.http, st)
	s.httpActive.Add(-1)
	st.ctx.ws = nil
	s.putState(st)
	t.SetContext(ws)
	s.wsAttach(ws, t, l)
	// The bytes after the handshake are frames.
	return s.wsTraffic(ws)
}

// checkHTTP enforces the timeouts of an HTTP connection; it runs on the
// loop.
func (s *Server) checkHTTP(st *connState, now int64) {
	t := st.t
	switch {
	case st.async:
		// The handler's goroutine decides.
	case st.blocked:
		if t.OutboundBuffered() <= s.maxOutboundBytes() {
			if s.httpTraffic(st) {
				_ = t.Close()
			}
		} else if d := s.writeTimeout(); d > 0 && now-st.blockedAt > d {
			_ = t.Close()
		}
	case st.reqStart != 0:
		hd, rd := s.readHeaderTimeout(), s.readTimeout()
		if hd > 0 && !st.headerDone && now-st.reqStart > hd || rd > 0 && now-st.reqStart > rd {
			s.requestTimeout(st)
		}
	case s.shutdown.Load():
		if t.OutboundBuffered() == 0 {
			_ = t.Close()
		}
	default:
		if d := s.idleTimeout(); d > 0 && now-st.lastActive > d {
			_ = t.Close()
		}
	}
}

// requestTimeout answers 408 to a request that did not arrive in time and
// closes the connection.
func (s *Server) requestTimeout(st *connState) {
	c := &st.ctx
	c.out, c.respStart = c.out[:0], 0
	c.reset()
	c.fail(408)
	_, _ = st.t.Write(c.out)
	_ = st.t.Close()
}

// serve is process plus the recovery of a panicking handler, which would
// otherwise take down the event loop and with it the whole server.
func (s *Server) serve(st *connState, buf []byte) (consumed int, closeConn bool) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("wisp: panic serving %s %s: %v\n%s", st.ctx.Method, st.ctx.Path, r, debug.Stack())
			st.stream = nil
			st.ctx.fail(500)
			closeConn = true
		}
	}()
	return s.process(st, buf)
}

var continueResponse = []byte("HTTP/1.1 100 Continue\r\n\r\n")

// process handles every complete request at the start of buf, appending the
// responses to st.ctx.out. It returns how many bytes of buf it consumed and
// whether the connection has to be closed once the responses are written.
func (s *Server) process(st *connState, buf []byte) (consumed int, closeConn bool) {
	c := &st.ctx
	c.req, c.srv, c.st = st.parser, s, st

	if st.stream != nil {
		n, done, cc := s.feedStream(st, buf)
		consumed = n
		if cc || !done {
			return consumed, cc
		}
	}

	for consumed < len(buf) {
		if len(c.out) >= s.maxOutboundBytes() {
			// Enough responses for a client that may not read them.
			st.blocked = true
			break
		}
		data := buf[consumed:]
		c.reset()

		n, err := st.parser.Parse(data)
		if err != nil {
			if err == wildcat.ErrMissingData && len(data) <= s.maxHeaderBytes() {
				break
			}
			if err == wildcat.ErrMissingData {
				c.fail(431)
			} else {
				c.fail(400)
			}
			return consumed, true
		}
		if n > s.maxHeaderBytes() {
			c.fail(431)
			return consumed, true
		}

		c.Method = st.parser.Method
		f, status := frame(st.parser)
		if status == 0 {
			status = c.setTarget(st.parser.Path)
		}
		if status == 0 && f.bodyLen > int64(s.maxBodyBytes()) && s.StreamHandler == nil {
			status = 413
		}
		if status != 0 {
			c.fail(status)
			return consumed, true
		}
		c.close = !f.keepAlive || s.shutdown.Load()

		var total int
		switch {
		case f.chunked:
			maxBody := s.maxBodyBytes()
			bn, need, status := scanChunked(data[n:], &st.chunk, int64(maxBody), 2*maxBody+s.maxHeaderBytes())
			if status != 0 {
				c.fail(status)
				return consumed, true
			}
			if bn == 0 {
				s.awaitBody(st, f, len(data) > n)
				if need > 0 {
					st.need = n + need
				}
				return consumed, false
			}
			total = n + bn
			c.Body = data[n : n+decodeChunked(data[n:total])]
			st.chunk = chunkScan{}

		case f.bodyLen > int64(s.maxBodyBytes()):
			fed, cc, wait := s.startStream(st, f, data[n:])
			consumed += n + fed
			if cc || wait {
				return consumed, cc
			}
			continue

		default:
			total = n + int(f.bodyLen)
			if len(data) < total {
				s.awaitBody(st, f, len(data) > n)
				st.need = total
				return consumed, false
			}
			c.Body = data[n:total]
		}
		st.continued, st.headerDone = false, false

		s.Handler(c)
		if c.ws != nil {
			// Upgraded: what follows is not HTTP any more.
			return consumed + total, false
		}
		consumed += total
		if st.async {
			// The response comes from a goroutine, and the next requests
			// wait for it.
			return consumed, false
		}
		if !c.responded {
			c.Status(204)
		}
		if c.close {
			return consumed, true
		}
	}

	return consumed, false
}

// awaitBody notes that the header of the current request is complete but
// not its body, and sends "100 Continue" if the client waits for it.
func (s *Server) awaitBody(st *connState, f framing, bodyStarted bool) {
	st.headerDone = true
	if f.expectContinue && !st.continued && !bodyStarted {
		st.ctx.out = append(st.ctx.out, continueResponse...)
		st.continued = true
	}
}

// startStream passes a request with a body over MaxBodyBytes to
// StreamHandler, then what arrived of the body to the BodyStream it set.
// It returns how much of body it consumed, whether the connection must be
// closed and whether the rest of the body is awaited.
func (s *Server) startStream(st *connState, f framing, body []byte) (fed int, closeConn, wait bool) {
	c := &st.ctx
	c.Body = nil
	s.StreamHandler(c)
	bs := c.bodyStream
	c.bodyStream = nil
	if bs == nil || bs.Data == nil || bs.End == nil || c.responded || c.ws != nil || st.async {
		// Refused: the body is not read, so the connection cannot go on.
		if !c.responded {
			c.fail(413)
		}
		c.close = true
		return 0, true, false
	}

	// What the request data aliases is about to be discarded.
	c.Method, c.Path, c.RawPath, c.Query, c.host = nil, nil, nil, nil, nil
	c.nparams = 0
	c.query.reset()
	st.parser.Headers = st.parser.Headers[:0]

	st.stream, st.streamLeft = bs, f.bodyLen
	s.awaitBody(st, f, len(body) > 0)
	st.continued = false
	n, done, cc := s.feedStream(st, body)
	return n, cc, !done
}

// framing is what the headers say about the extent of a request and the
// fate of its connection.
type framing struct {
	bodyLen        int64
	chunked        bool
	keepAlive      bool
	expectContinue bool
}

// frame returns a non-zero status if the request must be rejected.
func frame(p *wildcat.HTTPParser) (f framing, status int) {
	// The parser checked the "HTTP/" DIGIT "." DIGIT syntax. A later 1.x is
	// served as 1.1 (RFC 9110, section 2.5).
	http11 := false
	switch {
	case p.Version[5] != '1':
		return f, 505
	case p.Version[7] != '0':
		http11 = true
		f.keepAlive = true
	}

	bodyLen := int64(-1)
	closeSeen, chunked := false, false
	hosts := 0

	for i := range p.Headers {
		h := &p.Headers[i]

		// The length filters out almost every header with one comparison.
		switch len(h.Name) {
		case len("Host"):
			if equalFold(h.Name, "Host") {
				hosts++
			}
		case len("Content-Length"):
			if equalFold(h.Name, "Content-Length") {
				// Repeated headers that disagree are a request smuggling vector.
				n := wildcat.ParseDecimal(h.Value)
				if n < 0 || (bodyLen >= 0 && n != bodyLen) {
					return f, 400
				}
				bodyLen = n
			}
		case len("Transfer-Encoding"):
			if equalFold(h.Name, "Transfer-Encoding") {
				// Only "chunked" alone: any other coding is not implemented.
				if chunked || !equalFold(trimOWS(h.Value), "chunked") {
					return f, 501
				}
				chunked = true
			}
		case len("Connection"):
			if equalFold(h.Name, "Connection") {
				if hasToken(h.Value, "close") {
					closeSeen = true
				} else if hasToken(h.Value, "keep-alive") {
					f.keepAlive = true
				}
			}
		case len("Expect"):
			if equalFold(h.Name, "Expect") && equalFold(h.Value, "100-continue") {
				f.expectContinue = true
			}
		}
	}

	// RFC 9112, section 3.2: exactly one Host in HTTP/1.1, at most one before.
	if hosts > 1 || http11 && hosts == 0 {
		return f, 400
	}
	if chunked {
		// Transfer-Encoding with Content-Length, or in HTTP/1.0, is how
		// requests are smuggled past proxies that read them differently
		// (RFC 9112, section 6.1).
		if bodyLen >= 0 || !http11 {
			return f, 400
		}
		f.chunked = true
	}
	if closeSeen {
		f.keepAlive = false
	}
	if bodyLen > 0 {
		f.bodyLen = bodyLen
	}
	return f, 0
}

// hasToken reports whether the comma-separated list contains token,
// ignoring ASCII case.
func hasToken(list []byte, token string) bool {
	for len(list) > 0 {
		item := list
		if i := bytes.IndexByte(list, ','); i >= 0 {
			item, list = list[:i], list[i+1:]
		} else {
			list = nil
		}
		if equalFold(bytes.Trim(item, " \t"), token) {
			return true
		}
	}
	return false
}
