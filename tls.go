package wisp

// HTTPS. gnet has no TLS, so TLS connections are served the way
// github.com/maurice2k/tcpserver serves them: a listener with tuned socket
// options (listen_*.go), several goroutines accepting on it, each connection
// handed to a pool of goroutines and wrapped with tls.Server, so crypto/tls
// does the work.
//
// What runs on a connection differs: not a blocking handler but the same
// event code as on gnet. A tlsConn is an event loop of its own: a reader
// goroutine turns each Read into a traffic event, a writer goroutine writes
// the responses and runs the tasks queued by other goroutines (WSConn.Send,
// Async responses, the timeout checks), and a mutex makes them take turns,
// as events take turns on a gnet loop.

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/panjf2000/gnet/v2"
)

// ListenAndServeTLS serves HTTPS on addr (":8443") with the certificate
// and key in the PEM files certFile and keyFile, until Shutdown is called.
// It can run next to ListenAndServe, on another address, for one Server.
func (s *Server) ListenAndServeTLS(addr, certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	ln, err := Listen(addr)
	if err != nil {
		return err
	}
	return s.ServeTLS(ln, &tls.Config{Certificates: []tls.Certificate{cert}})
}

// ServeTLS serves HTTPS on ln with config until Shutdown is called; ln is
// closed then. config is cloned, and offers "http/1.1" by ALPN if its
// NextProtos is empty. Listen returns a listener tuned for it.
func (s *Server) ServeTLS(ln net.Listener, config *tls.Config) error {
	if s.Handler == nil {
		return errors.New("wisp: Server.Handler is nil")
	}
	if config == nil || len(config.Certificates) == 0 && config.GetCertificate == nil && config.GetConfigForClient == nil {
		return errors.New("wisp: ServeTLS needs a certificate")
	}
	cfg := config.Clone()
	if len(cfg.NextProtos) == 0 {
		cfg.NextProtos = []string{"http/1.1"}
	}

	tl := &tlsListener{Listener: ln}
	s.mu.Lock()
	if s.shutdown.Load() {
		s.mu.Unlock()
		_ = ln.Close()
		return errors.New("wisp: server is shut down")
	}
	if s.listeners == nil {
		s.listeners = make(map[*tlsListener]struct{})
	}
	s.listeners[tl] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.listeners, tl)
		s.mu.Unlock()
	}()

	s.started.Store(true)
	s.startSweeper()

	loops := s.TLSAcceptLoops
	if loops <= 0 {
		loops = min(runtime.GOMAXPROCS(0), 8)
	}
	errc := make(chan error, loops)
	for range loops {
		go func() { errc <- s.acceptLoop(tl, cfg) }()
	}
	var first error
	for range loops {
		if err := <-errc; err != nil && first == nil {
			first = err
			_ = tl.Close()
		}
	}
	return first
}

// Listen returns a TCP listener for ServeTLS, set up as tcpserver sets its
// own: SO_REUSEPORT, so that another process (a new version of the server)
// can listen on the same port, and on Linux TCP_FASTOPEN and
// TCP_DEFER_ACCEPT, which wakes the server only once the client has sent its
// first bytes (the TLS ClientHello).
func Listen(addr string) (net.Listener, error) {
	lc := net.ListenConfig{Control: listenControl}
	return lc.Listen(context.Background(), "tcp", addr)
}

// tlsListener is a listener that Shutdown and a failing accept loop may
// both close.
type tlsListener struct {
	net.Listener
	once sync.Once
	err  error
}

func (l *tlsListener) Close() error {
	l.once.Do(func() { l.err = l.Listener.Close() })
	return l.err
}

// acceptLoop accepts connections until ln is closed.
func (s *Server) acceptLoop(ln *tlsListener, cfg *tls.Config) error {
	var delay time.Duration
	for {
		nc, err := ln.Accept()
		if err != nil {
			if s.shutdown.Load() || errors.Is(err, net.ErrClosed) {
				return nil
			}
			// Out of file descriptors and the like: wait for some to be
			// released, as net/http and tcpserver do.
			if te, ok := err.(interface{ Temporary() bool }); ok && te.Temporary() {
				delay = min(max(2*delay, 5*time.Millisecond), time.Second)
				time.Sleep(delay)
				continue
			}
			return err
		}
		delay = 0
		if !s.conns.submit(func() { s.serveTLSConn(nc, cfg) }, 0) {
			_ = nc.Close()
		}
	}
}

// serveTLSConn runs the handshake, then serves the connection until it is
// closed; it runs on a goroutine of the pool.
func (s *Server) serveTLSConn(nc net.Conn, cfg *tls.Config) {
	conn := tls.Server(nc, cfg)
	if d := s.readHeaderTimeout(); d > 0 {
		_ = conn.SetDeadline(time.Now().Add(time.Duration(d)))
	}
	if err := conn.Handshake(); err != nil || s.shutdown.Load() {
		_ = conn.Close()
		return
	}
	_ = conn.SetDeadline(time.Time{})

	tc := &tlsConn{
		s:          s,
		nc:         conn,
		kick:       make(chan struct{}, 1),
		writerDone: make(chan struct{}),
	}
	tc.serve()
}

// readBufPool holds the buffers TLS connections read into.
var readBufPool = sync.Pool{New: func() any { b := make([]byte, 16<<10); return &b }}

// tlsConn is a TLS connection as a transport. The transport methods are
// called with mu held, which is what being on the loop means here.
type tlsConn struct {
	s    *Server
	nc   net.Conn
	loop *loop

	mu      sync.Mutex
	state   any    // *connState or *WSConn
	in      []byte // received; in[inOff:] is not consumed yet
	inOff   int
	out     []byte // written, not handed to the socket yet
	spare   []byte
	writing int  // handed to the socket, not written yet
	closing bool // close once out is written
	closed  bool // the connection is gone: tasks are dropped

	gone       atomic.Bool
	taskMu     sync.Mutex
	tasks      []gnet.Runnable
	kick       chan struct{} // wakes the writer
	writerDone chan struct{}
}

func (tc *tlsConn) Peek(int) ([]byte, error) { return tc.in[tc.inOff:], nil }

func (tc *tlsConn) Discard(n int) (int, error) {
	tc.inOff += n
	if tc.inOff >= len(tc.in) {
		tc.in, tc.inOff = tc.in[:0], 0
	}
	return n, nil
}

func (tc *tlsConn) InboundBuffered() int { return len(tc.in) - tc.inOff }

func (tc *tlsConn) Write(p []byte) (int, error) {
	if tc.closed {
		return 0, net.ErrClosed
	}
	tc.out = append(tc.out, p...)
	tc.wake()
	return len(p), nil
}

func (tc *tlsConn) OutboundBuffered() int { return len(tc.out) + tc.writing }

func (tc *tlsConn) Context() any         { return tc.state }
func (tc *tlsConn) SetContext(state any) { tc.state = state }
func (tc *tlsConn) RemoteAddr() net.Addr { return tc.nc.RemoteAddr() }
func (tc *tlsConn) isTLS() bool          { return true }

func (tc *tlsConn) Close() error {
	tc.closing = true
	tc.wake()
	return nil
}

func (tc *tlsConn) execute(r gnet.Runnable) error {
	tc.taskMu.Lock()
	if tc.gone.Load() {
		tc.taskMu.Unlock()
		return net.ErrClosed
	}
	tc.tasks = append(tc.tasks, r)
	tc.taskMu.Unlock()
	tc.wake()
	return nil
}

func (tc *tlsConn) wake() {
	select {
	case tc.kick <- struct{}{}:
	default:
	}
}

// serve is the reader: it turns what arrives into traffic events until the
// connection is closed.
func (tc *tlsConn) serve() {
	s := tc.s
	tc.loop = newLoop(s, tc.execute)
	s.addLoop(tc, tc.loop)
	tc.mu.Lock()
	s.openHTTP(tc, tc.loop)
	tc.mu.Unlock()
	go tc.writer()

	// Reading into a buffer of its own, not into in, lets tasks consume in
	// while the reader waits.
	rbuf := readBufPool.Get().(*[]byte)
	for {
		n, err := tc.nc.Read(*rbuf)
		tc.mu.Lock()
		if n > 0 && !tc.closing {
			if tc.inOff > 0 {
				tc.in = tc.in[:copy(tc.in, tc.in[tc.inOff:])]
				tc.inOff = 0
			}
			tc.in = append(tc.in, (*rbuf)[:n]...)
			if s.traffic(tc.state) {
				tc.Close()
			}
		}
		if err != nil {
			// What is queued is still written, then the writer closes.
			tc.Close()
		}
		tc.mu.Unlock()
		if err != nil {
			break
		}
	}
	readBufPool.Put(rbuf)
	<-tc.writerDone

	tc.taskMu.Lock()
	tc.gone.Store(true)
	tc.tasks = nil
	tc.taskMu.Unlock()
	tc.mu.Lock()
	tc.closed = true
	s.closed(tc.state)
	tc.state, tc.in, tc.out, tc.spare = nil, nil, nil, nil
	tc.mu.Unlock()
	s.removeLoop(tc)
}

// writer writes what the events and the tasks queue, and closes the
// connection once it is closing and everything is written.
func (tc *tlsConn) writer() {
	defer close(tc.writerDone)
	defer tc.nc.Close()
	for range tc.kick {
		for {
			tc.runTasks()

			tc.mu.Lock()
			out := tc.out
			if len(out) == 0 {
				closing := tc.closing
				tc.mu.Unlock()
				if closing {
					return
				}
				break
			}
			tc.out, tc.spare, tc.writing = tc.spare, nil, len(out)
			tc.mu.Unlock()

			if d := tc.s.writeTimeout(); d > 0 {
				_ = tc.nc.SetWriteDeadline(time.Now().Add(time.Duration(d)))
			}
			_, err := tc.nc.Write(out)

			tc.mu.Lock()
			tc.writing = 0
			if cap(out) <= maxPooledBuffer && tc.spare == nil {
				tc.spare = out[:0]
			}
			tc.mu.Unlock()
			if err != nil {
				return
			}
		}
	}
}

func (tc *tlsConn) runTasks() {
	tc.taskMu.Lock()
	tasks := tc.tasks
	tc.tasks = nil
	tc.taskMu.Unlock()
	if len(tasks) == 0 {
		return
	}
	tc.mu.Lock()
	defer tc.mu.Unlock()
	for _, r := range tasks {
		if !tc.closed {
			_ = r.Run(context.Background())
		}
	}
}

// closeTLSConns closes what is left of the TLS connections, at the end of
// Shutdown.
func (s *Server) closeTLSConns() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key := range s.loops {
		if tc, ok := key.(*tlsConn); ok {
			_ = tc.nc.Close()
		}
	}
}
