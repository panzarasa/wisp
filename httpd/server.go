// Package httpd is a small HTTP/1.1 server on top of gnet: requests are parsed
// in place with the embedded wildcat parser and dispatched by a Router.
// A handler can switch its connection to WebSocket (RFC 6455) with
// Ctx.Upgrade: the same gnet connection then carries frames (websocket.go).
//
// Handlers run on gnet's event loops, so a handler that blocks stalls every
// connection of its loop: hand slow work to a goroutine pool and answer from
// there with gnet's AsyncWrite, which this first version does not wrap yet.
//
// Not supported yet: chunked request bodies (answered with 501), TLS,
// HTTP/2, percent-decoding of paths, idle/read timeouts on HTTP connections
// and a bound on the responses queued for a client that pipelines without
// reading. WebSocket connections have their own timeouts and limits, but no
// extensions (permessage-deflate).
package httpd

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
	DefaultMaxHeaderBytes = 64 << 10
	DefaultMaxBodyBytes   = 4 << 20

	// Response buffers that grew beyond this are not kept for reuse.
	maxPooledBuffer = 64 << 10
)

// Server serves HTTP/1.1 over gnet. The zero value needs only a Handler.
type Server struct {
	Handler Handler

	// MaxHeaderBytes limits the request line plus headers
	// (DefaultMaxHeaderBytes if zero); larger requests get a 431.
	MaxHeaderBytes int
	// MaxBodyBytes limits Content-Length (DefaultMaxBodyBytes if zero);
	// larger requests get a 413. Bodies are buffered whole before the
	// handler runs.
	MaxBodyBytes int

	engine atomic.Pointer[gnet.Engine]
	pool   sync.Pool

	// WebSocket connections, per event loop (websocket.go).
	wsMu       sync.Mutex
	wsLoops    map[gnet.EventLoop]*wsLoop
	wsActive   atomic.Int64
	wsTick     atomic.Int64 // nanoseconds between timeout checks
	wsShutdown atomic.Bool
}

// connState is what a connection keeps between events.
type connState struct {
	parser *wildcat.HTTPParser
	ctx    Ctx

	// When a request is only partially buffered: the bytes it needs in
	// total, so the events that bring the rest of a large body do not
	// re-parse it.
	need int
	// A "100 Continue" was already sent for the request being buffered.
	continued bool
}

// ListenAndServe serves on addr (":8080" or a gnet address such as
// "tcp://127.0.0.1:8080") until Shutdown is called or gnet fails.
func (s *Server) ListenAndServe(addr string, opts ...gnet.Option) error {
	if s.Handler == nil {
		return errors.New("httpd: Server.Handler is nil")
	}
	if !strings.Contains(addr, "://") {
		addr = "tcp://" + addr
	}
	// The ticker drives the WebSocket timeouts.
	opts = append(opts, gnet.WithTicker(true))
	return gnet.Run(&eventHandler{s: s}, addr, opts...)
}

// Shutdown stops the server; ListenAndServe then returns. WebSocket
// connections are closed first with 1001 "going away", and given until ctx
// expires to answer; HTTP connections are closed right away.
func (s *Server) Shutdown(ctx context.Context) error {
	eng := s.engine.Load()
	if eng == nil {
		return errors.New("httpd: server is not running")
	}
	s.wsShutdownAll(ctx)
	// Stop stops the engine even when ctx has already expired.
	return eng.Stop(ctx)
}

func (s *Server) maxHeaderBytes() int {
	if s.MaxHeaderBytes > 0 {
		return s.MaxHeaderBytes
	}
	return DefaultMaxHeaderBytes
}

func (s *Server) maxBodyBytes() int {
	if s.MaxBodyBytes > 0 {
		return s.MaxBodyBytes
	}
	return DefaultMaxBodyBytes
}

func (s *Server) getState() *connState {
	if st, ok := s.pool.Get().(*connState); ok {
		return st
	}
	return &connState{parser: wildcat.NewHTTPParser()}
}

func (s *Server) putState(st *connState) {
	out, extra := st.ctx.out[:0], st.ctx.extra[:0]
	if cap(out) > maxPooledBuffer {
		out = nil
	}
	// Drop every reference into the connection's buffers.
	st.ctx = Ctx{out: out, extra: extra}
	st.need, st.continued = 0, false
	s.pool.Put(st)
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
	c.SetContext(h.s.getState())
	return nil, gnet.None
}

func (h *eventHandler) OnClose(c gnet.Conn, _ error) gnet.Action {
	switch st := c.Context().(type) {
	case *connState:
		c.SetContext(nil)
		h.s.putState(st)
	case *WSConn:
		c.SetContext(nil)
		h.s.wsDetach(st)
	}
	return gnet.None
}

func (h *eventHandler) OnTick() (time.Duration, gnet.Action) {
	h.s.wsSweep()
	return h.s.wsTickInterval(), gnet.None
}

func (h *eventHandler) OnTraffic(c gnet.Conn) gnet.Action {
	st, ok := c.Context().(*connState)
	if !ok {
		return h.s.wsTraffic(c, c.Context().(*WSConn))
	}

	if st.need > 0 {
		if c.InboundBuffered() < st.need {
			return gnet.None
		}
		st.need = 0
	}

	// Peek, not Next: an incomplete request stays in gnet's inbound buffer
	// and is seen again, followed by the new bytes, on the next event.
	buf, _ := c.Peek(-1)

	st.ctx.out = st.ctx.out[:0]
	st.ctx.conn = c
	consumed, closeConn := h.s.serve(st, buf)
	ws := st.ctx.ws

	// Discard(0) would drop the whole buffer.
	if consumed > 0 {
		_, _ = c.Discard(consumed)
	}
	if len(st.ctx.out) > 0 {
		// Write copies what the socket does not take, so out can be reused.
		if _, err := c.Write(st.ctx.out); err != nil {
			return gnet.Close
		}
	}
	if closeConn {
		if ws != nil {
			ws.discard()
		}
		return gnet.Close
	}
	if ws != nil {
		// The connection is a WebSocket from now on: the HTTP state goes
		// back to the pool, and the bytes after the handshake are frames.
		st.ctx.ws = nil
		h.s.putState(st)
		c.SetContext(ws)
		h.s.wsAttach(c, ws)
		return h.s.wsTraffic(c, ws)
	}
	return gnet.None
}

// serve is process plus the recovery of a panicking handler, which would
// otherwise take down the event loop and with it the whole server.
func (s *Server) serve(st *connState, buf []byte) (consumed int, closeConn bool) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("httpd: panic serving %s %s: %v\n%s", st.ctx.Method, st.ctx.Path, r, debug.Stack())
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
	c.req = st.parser
	c.srv = s

	for consumed < len(buf) {
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

		f, status := frame(st.parser)
		if status == 0 && f.bodyLen > int64(s.maxBodyBytes()) {
			status = 413
		}
		if status != 0 {
			c.fail(status)
			return consumed, true
		}

		total := n + int(f.bodyLen)
		if len(data) < total {
			if f.expectContinue && !st.continued {
				c.out = append(c.out, continueResponse...)
				st.continued = true
			}
			st.need = total
			break
		}
		st.continued = false

		c.Method = st.parser.Method
		c.Path, c.Query = st.parser.Path, nil
		if i := bytes.IndexByte(c.Path, '?'); i >= 0 {
			c.Path, c.Query = c.Path[:i], c.Path[i+1:]
		}
		c.Body = data[n:total]
		c.close = !f.keepAlive

		s.Handler(c)
		if c.ws != nil {
			// Upgraded: what follows is not HTTP any more.
			return consumed + total, false
		}
		if !c.responded {
			c.Status(204)
		}

		consumed += total
		if c.close {
			return consumed, true
		}
	}

	return consumed, false
}

// framing is what the headers say about the extent of a request and the
// fate of its connection.
type framing struct {
	bodyLen        int64
	keepAlive      bool
	expectContinue bool
}

// frame returns a non-zero status if the request must be rejected.
func frame(p *wildcat.HTTPParser) (f framing, status int) {
	switch string(p.Version) {
	case "HTTP/1.1":
		f.keepAlive = true
	case "HTTP/1.0":
	default:
		return f, 505
	}

	bodyLen := int64(-1)
	closeSeen := false

	for i := range p.Headers {
		h := &p.Headers[i]

		// The length filters out almost every header with one comparison.
		switch len(h.Name) {
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
				return f, 501
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
