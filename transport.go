package wisp

// What the HTTP and WebSocket code need from a connection, and where it is
// served: a gnet connection on its event loop, or a TLS connection served by
// its own goroutines (tls.go). Both run the same code, one event at a time
// per connection.

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/panjf2000/gnet/v2"
)

// transport is a connection. Every method but execute must be called on the
// connection's loop.
type transport interface {
	// Peek returns the buffered input; it stays buffered until Discard.
	Peek(n int) ([]byte, error)
	Discard(n int) (int, error)
	InboundBuffered() int
	// Write never blocks: what the socket does not take at once is buffered,
	// and p can be reused when Write returns.
	Write(p []byte) (int, error)
	OutboundBuffered() int
	// Context is the connection's state: a *connState or a *WSConn.
	Context() any
	SetContext(ctx any)
	RemoteAddr() net.Addr
	// Close writes what is buffered, then closes the connection.
	Close() error

	// execute queues r to run on the connection's loop. It may be called
	// from any goroutine, the loop included; r always runs later.
	execute(r gnet.Runnable) error
	isTLS() bool
}

// gnetConn is a gnet connection as a transport.
type gnetConn struct {
	gnet.Conn
}

func (c *gnetConn) execute(r gnet.Runnable) error {
	return c.EventLoop().Execute(context.Background(), r)
}

func (*gnetConn) isTLS() bool { return false }

// loop is where a set of connections is served: a gnet event loop, or one
// TLS connection. Its maps are only touched on the loop.
type loop struct {
	s    *Server
	exec func(gnet.Runnable) error
	http map[*connState]struct{}
	ws   map[*WSConn]struct{}
}

func newLoop(s *Server, exec func(gnet.Runnable) error) *loop {
	return &loop{
		s:    s,
		exec: exec,
		http: make(map[*connState]struct{}),
		ws:   make(map[*WSConn]struct{}),
	}
}

// Run checks the timeouts of the loop's connections, on the loop.
func (l *loop) Run(context.Context) error {
	now := monotime()
	for st := range l.http {
		l.s.checkHTTP(st, now)
	}
	for ws := range l.ws {
		ws.checkTimeouts(now)
	}
	return nil
}

// addLoop registers a loop under key: a gnet.EventLoop or a *tlsConn.
func (s *Server) addLoop(key any, l *loop) {
	s.mu.Lock()
	if s.loops == nil {
		s.loops = make(map[any]*loop)
	}
	s.loops[key] = l
	s.mu.Unlock()
}

func (s *Server) removeLoop(key any) {
	s.mu.Lock()
	delete(s.loops, key)
	s.mu.Unlock()
}

// gnetLoop returns the loop of a gnet event loop, creating it on first use.
func (s *Server) gnetLoop(el gnet.EventLoop) *loop {
	s.mu.Lock()
	defer s.mu.Unlock()
	if l := s.loops[el]; l != nil {
		return l
	}
	if s.loops == nil {
		s.loops = make(map[any]*loop)
	}
	l := newLoop(s, func(r gnet.Runnable) error {
		return el.Execute(context.Background(), r)
	})
	s.loops[el] = l
	return l
}

// eachLoop queues r on every loop.
func (s *Server) eachLoop(r func(l *loop) gnet.Runnable) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range s.loops {
		_ = l.exec(r(l))
	}
}

var epoch = time.Now()

// monotime is a monotonic clock in nanoseconds.
func monotime() int64 {
	return int64(time.Since(epoch))
}

// Timeouts are checked every quarter of the shortest one, within these
// bounds, by a goroutine of the server's own: gnet's ticker would only
// start after a second, and TLS connections have no ticker.
const (
	maxTick = time.Second
	minTick = 10 * time.Millisecond
)

// startSweeper starts the goroutine that checks the timeouts; Shutdown stops
// it.
func (s *Server) startSweeper() {
	s.sweepOnce.Do(func() {
		s.retick = make(chan struct{}, 1)
		s.stopSweep = make(chan struct{})
		for _, d := range []int64{s.readHeaderTimeout(), s.readTimeout(), s.writeTimeout(), s.idleTimeout()} {
			if d > 0 {
				s.lowerTick(d / 4)
			}
		}
		go s.sweeper()
	})
}

func (s *Server) sweeper() {
	t := time.NewTimer(s.tickInterval())
	defer t.Stop()
	for {
		select {
		case <-s.stopSweep:
			return
		case <-s.retick:
			// A shorter timeout arrived: do not wait for the old interval.
			t.Reset(s.tickInterval())
			continue
		case <-t.C:
		}
		s.eachLoop(func(l *loop) gnet.Runnable { return l })
		t.Reset(s.tickInterval())
	}
}

// lowerTick makes the timeouts be checked at least every d.
func (s *Server) lowerTick(d int64) {
	d = max(d, int64(minTick))
	for {
		cur := s.tick.Load()
		if cur != 0 && cur <= d {
			return
		}
		if s.tick.CompareAndSwap(cur, d) {
			break
		}
	}
	if s.retick != nil {
		select {
		case s.retick <- struct{}{}:
		default:
		}
	}
}

func (s *Server) tickInterval() time.Duration {
	if d := time.Duration(s.tick.Load()); d > 0 && d < maxTick {
		return d
	}
	return maxTick
}

// workerPool runs functions on goroutines that are kept for a while after
// their work, as fasthttp and maurice2k/tcpserver do: starting a goroutine
// for every task costs more, mostly in stack growth.
type workerPool struct {
	once  sync.Once
	ready chan func() // unbuffered: a send succeeds only if a worker is idle
	n     atomic.Int64
}

const workerIdle = 10 * time.Second

// submit runs fn on an idle worker or a new one; it returns false, without
// running fn, if limit (when positive) workers are busy already.
func (p *workerPool) submit(fn func(), limit int) bool {
	p.once.Do(func() { p.ready = make(chan func()) })
	select {
	case p.ready <- fn:
		return true
	default:
	}
	if n := p.n.Add(1); limit > 0 && n > int64(limit) {
		p.n.Add(-1)
		return false
	}
	go p.work(fn)
	return true
}

func (p *workerPool) work(fn func()) {
	defer p.n.Add(-1)
	idle := time.NewTimer(workerIdle)
	defer idle.Stop()
	for {
		fn()
		idle.Reset(workerIdle)
		select {
		case fn = <-p.ready:
		case <-idle.C:
			return
		}
	}
}
