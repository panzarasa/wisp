package wisp

import (
	"context"
	"log"
	"runtime/debug"

	"github.com/panzarasa/wisp/wildcat"
)

// Async answers the request from a goroutine of the server's pool, where fn
// may block (a database, another service) without stalling the event loop.
// fn gets a copy of the request, valid until it returns, and writes the
// response on it as a handler does. Async returns at once, and the handler
// must not use c afterwards.
//
// Responses keep the order of the requests: the requests a client
// pipelines behind this one wait for its response. When MaxAsync handlers
// are running already, the request gets a 503 instead. An Async handler
// cannot Upgrade.
func (c *Ctx) Async(fn Handler) {
	if c.st == nil || c.detached || c.ws != nil {
		// Already on a goroutine, or outside a connection (tests).
		fn(c)
		return
	}
	s, st, t := c.srv, c.st, c.conn
	ac := c.detach()
	ok := s.async.submit(func() {
		runAsync(ac, fn)
		if err := t.execute(&asyncDone{s: s, st: st, ac: ac}); err != nil {
			// The server is stopping and closes the connection anyway.
			return
		}
	}, s.maxAsync())
	if !ok {
		c.Text(503, statusText(503))
		return
	}
	st.async = true
	c.responded = true
}

// runAsync runs an Async handler, recovering a panic as serve does.
func runAsync(ac *Ctx, fn Handler) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("wisp: panic serving %s %s: %v\n%s", ac.Method, ac.Path, r, debug.Stack())
			ac.fail(500)
		}
	}()
	fn(ac)
	if !ac.responded {
		ac.Status(204)
	}
}

// asyncDone sends the response of an Async handler, on the connection's
// loop, and serves the requests that waited for it.
type asyncDone struct {
	s  *Server
	st *connState
	ac *Ctx
}

func (d *asyncDone) Run(context.Context) error {
	st := d.st
	if st.dead || !st.async {
		return nil // the connection is gone
	}
	st.async = false
	t := st.t
	if _, err := t.Write(d.ac.out); err != nil || d.ac.close {
		_ = t.Close()
		return nil
	}
	st.lastActive = monotime()
	if t.OutboundBuffered() > d.s.maxOutboundBytes() {
		st.blocked, st.blockedAt = true, st.lastActive
	}
	if t.InboundBuffered() > 0 && d.s.httpTraffic(st) {
		_ = t.Close()
	}
	return nil
}

// detach copies the request into a Ctx of its own, for an Async handler.
func (c *Ctx) detach() *Ctx {
	n := len(c.Method) + len(c.Path) + len(c.RawPath) + len(c.Query) + len(c.Body) + len(c.host) + len(c.req.Version)
	for _, h := range c.req.Headers {
		n += len(h.Name) + len(h.Value)
	}
	for i := 0; i < c.nparams; i++ {
		n += len(c.params[i].value)
	}
	// One allocation for every byte; buf never grows, so the slices taken
	// from it stay valid.
	buf := make([]byte, 0, n)
	cp := func(b []byte) []byte {
		if b == nil {
			return nil
		}
		start := len(buf)
		buf = append(buf, b...)
		return buf[start:len(buf):len(buf)]
	}

	req := &wildcat.HTTPParser{Headers: make([]wildcat.Header, len(c.req.Headers))}
	for i, h := range c.req.Headers {
		req.Headers[i] = wildcat.Header{Name: cp(h.Name), Value: cp(h.Value)}
	}
	ac := &Ctx{
		Method:   cp(c.Method),
		Path:     cp(c.Path),
		RawPath:  cp(c.RawPath),
		Query:    cp(c.Query),
		Body:     cp(c.Body),
		req:      req,
		srv:      c.srv,
		conn:     c.conn,
		host:     cp(c.host),
		nparams:  c.nparams,
		extra:    append([]byte(nil), c.extra...),
		close:    c.close,
		head:     c.head,
		detached: true,
	}
	req.Method, req.Path, req.Version = ac.Method, ac.RawPath, cp(c.req.Version)
	for i := 0; i < c.nparams; i++ {
		ac.params[i] = param{c.params[i].key, cp(c.params[i].value)}
	}
	return ac
}
