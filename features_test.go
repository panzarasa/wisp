package wisp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// echoTarget answers with what the server made of the request target.
func echoTarget(c *Ctx) {
	c.Text(200, fmt.Sprintf("path=%s raw=%s query=%s host=%s", c.Path, c.RawPath, c.Query, c.Host()))
}

func TestRequestTargets(t *testing.T) {
	for _, tc := range []struct {
		target string
		status int
		want   string
	}{
		{"/a/b?x=1", 200, "path=/a/b raw=/a/b query=x=1 host=h"},
		{"/caf%C3%A9", 200, "path=/café raw=/caf%C3%A9 query= host=h"},
		{"/a%2Fb", 200, "path=/a%2Fb raw=/a%2Fb query= host=h"},
		{"http://example.com/p?q", 200, "path=/p raw=/p query=q host=example.com"},
		{"HTTPS://example.com:8443", 200, "path=/ raw=/ query= host=example.com:8443"},
		{"http://example.com?q=1", 200, "path=/ raw=/ query=q=1 host=example.com"},
		{"http://user@example.com/", 400, ""},
		{"ftp://example.com/", 400, ""},
		{"http:///p", 400, ""},
		{"*", 400, ""}, // not OPTIONS
		{"/a/../b", 400, ""},
		{"/a/./b", 400, ""},
		{"/a/%2e%2e/b", 400, ""},
		{"/..", 400, ""},
		{"/a%00", 400, ""},
		{"/a%zz", 400, ""},
		{"/a%2", 400, ""},
		{"/a..b/.c", 200, "path=/a..b/.c raw=/a..b/.c query= host=h"},
		{"a/b", 400, ""},
	} {
		s := &Server{Handler: echoTarget}
		st := s.getState()
		resps, bodies, _, _ := feed(t, s, st, "GET "+tc.target+" HTTP/1.1\r\nHost: h\r\n\r\n")
		if len(resps) != 1 || resps[0].StatusCode != tc.status || tc.want != "" && bodies[0] != tc.want {
			t.Errorf("%s: got %v %q, want %d %q", tc.target, resps, bodies, tc.status, tc.want)
		}
	}

	s := &Server{Handler: echoTarget}
	st := s.getState()
	resps, bodies, _, _ := feed(t, s, st, "OPTIONS * HTTP/1.1\r\nHost: h\r\n\r\n")
	if len(resps) != 1 || resps[0].StatusCode != 200 || bodies[0] != "path=* raw=* query= host=h" {
		t.Errorf("OPTIONS *: %v %q", resps, bodies)
	}
}

func TestRequestFraming(t *testing.T) {
	for _, tc := range []struct {
		name    string
		request string
		status  int
	}{
		{"no Host in 1.1", "GET / HTTP/1.1\r\n\r\n", 400},
		{"two Hosts", "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n", 400},
		{"no Host in 1.0", "GET / HTTP/1.0\r\n\r\n", 200},
		{"HTTP/1.2 as 1.1", "GET / HTTP/1.2\r\nHost: h\r\n\r\n", 200},
		{"HTTP/2.0", "GET / HTTP/2.0\r\nHost: h\r\n\r\n", 505},
		{"TE and CL", "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n0\r\n\r\n", 400},
		{"TE in 1.0", "POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", 400},
		{"two TE", "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", 501},
		{"control byte in value", "GET / HTTP/1.1\r\nHost: h\r\nX: a\x01b\r\n\r\n", 400},
		{"space before colon", "GET / HTTP/1.1\r\nHost : h\r\n\r\n", 400},
		{"lowercase method is a token", "get / HTTP/1.1\r\nHost: h\r\n\r\n", 200},
		{"bad method", "G(T / HTTP/1.1\r\nHost: h\r\n\r\n", 400},
	} {
		s := &Server{Handler: func(c *Ctx) { c.Status(200) }}
		st := s.getState()
		resps, _, _, _ := feed(t, s, st, tc.request)
		if len(resps) != 1 || resps[0].StatusCode != tc.status {
			t.Errorf("%s: got %v, want %d", tc.name, resps, tc.status)
		}
	}
}

func TestChunkedBody(t *testing.T) {
	const head = "POST /echo HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
	for _, tc := range []struct {
		name   string
		body   string
		status int
		want   string
	}{
		{"simple", "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n", 200, "hello world"},
		{"empty", "0\r\n\r\n", 200, ""},
		{"extensions", "5;a=b\r\nhello\r\n0;x\r\n\r\n", 200, "hello"},
		{"upper hex", "A\r\n0123456789\r\n0\r\n\r\n", 200, "0123456789"},
		{"trailers", "3\r\nabc\r\n0\r\nX-Sum: 1\r\nY: 2\r\n\r\n", 200, "abc"},
		{"bare LF", "3\nabc\r\n0\r\n\r\n", 400, ""},
		{"bad chunk end", "3\r\nabcX\r\n0\r\n\r\n", 400, ""},
		{"bad size", "zz\r\nabc\r\n0\r\n\r\n", 400, ""},
		{"no size", "\r\n", 400, ""},
		{"huge size", "1000000000000000\r\n", 400, ""},
		{"too large", "401\r\n", 413, ""},
		{"too large in total", "200\r\n" + strings.Repeat("a", 0x200) + "\r\n201\r\n", 413, ""},
		{"bad trailer", "0\r\nX: \x01\r\n\r\n", 400, ""},
	} {
		s := &Server{Handler: testHandler(), MaxBodyBytes: 1024}
		st := s.getState()
		req := head + tc.body
		resps, bodies, consumed, _ := feed(t, s, st, req)
		if len(resps) != 1 || resps[0].StatusCode != tc.status || tc.status == 200 && (bodies[0] != tc.want || consumed != len(req)) {
			t.Errorf("%s: got %v %q, consumed %d of %d", tc.name, resps, bodies, consumed, len(req))
		}
	}

	// Byte by byte, then followed by a pipelined request.
	s := &Server{Handler: testHandler()}
	st := s.getState()
	req := head + "5\r\nhello\r\n6\r\n world\r\n0\r\nT: x\r\n\r\n"
	for i := 1; i < len(req); i++ {
		resps, _, consumed, closed := feed(t, s, st, req[:i])
		if len(resps) != 0 || consumed != 0 || closed {
			t.Fatalf("prefix %d: %d responses, consumed %d, closed %v", i, len(resps), consumed, closed)
		}
		if st.need > i {
			i = st.need - 1 // as httpTraffic does, skip events that cannot complete it
		}
	}
	st.need = 0
	all := req + "GET /users/9 HTTP/1.1\r\nHost: h\r\n\r\n"
	_, bodies, consumed, _ := feed(t, s, st, all)
	if len(bodies) != 2 || bodies[0] != "hello world" || bodies[1] != "9" || consumed != len(all) {
		t.Fatalf("got %q, consumed %d of %d", bodies, consumed, len(all))
	}
}

func TestChunkedContinue(t *testing.T) {
	s := &Server{Handler: testHandler()}
	st := s.getState()
	head := "POST /echo HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nExpect: 100-continue\r\n\r\n"
	if _, closed := s.serve(st, []byte(head)); closed || string(st.ctx.out) != string(continueResponse) {
		t.Fatalf("got %q", st.ctx.out)
	}
	_, bodies, _, _ := feed(t, s, st, head+"2\r\nok\r\n0\r\n\r\n")
	if len(bodies) != 1 || bodies[0] != "ok" {
		t.Fatalf("got %q", bodies)
	}
}

func TestQueryAndForm(t *testing.T) {
	var got []string
	s := &Server{Handler: func(c *Ctx) {
		got = append(got, fmt.Sprintf("a=%q b=%q none=%v empty=%q", c.QueryParam("a"), c.QueryParam("b"), c.QueryParam("none") == nil, c.QueryParam("e")))
		c.VisitQuery(func(k, v []byte) bool { got = append(got, string(k)+"="+string(v)); return true })
		got = append(got, fmt.Sprintf("form x=%q", c.FormParam("x")))
		c.VisitForm(func(k, v []byte) bool { got = append(got, "form "+string(k)+"="+string(v)); return true })
		c.Status(200)
	}}
	st := s.getState()
	body := "x=1%2B1&y=a+b"
	feed(t, s, st, "POST /?a=hello+world&b=%E2%82%AC&e&a=2&bad=%zz HTTP/1.1\r\nHost: h\r\n"+
		"Content-Type: application/x-www-form-urlencoded; charset=utf-8\r\nContent-Length: "+fmt.Sprint(len(body))+"\r\n\r\n"+body)
	want := []string{
		`a="hello world" b="€" none=true empty=""`,
		"a=hello world", "b=€", "e=", "a=2", "bad=%zz",
		`form x="1+1"`, "form x=1+1", "form y=a b",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	// The parameters of a request do not leak into the next one, and a body
	// of another type has no form.
	got = nil
	feed(t, s, st, "POST /?b=1 HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nx=1")
	if got[0] != `a="" b="1" none=true empty=""` || got[len(got)-1] != `form x=""` {
		t.Fatalf("got %q", got)
	}
}

func TestOutboundLimit(t *testing.T) {
	s := &Server{Handler: testHandler(), MaxOutboundBytes: 300}
	st := s.getState()
	req := "GET / HTTP/1.1\r\nHost: h\r\n\r\n"
	resps, _, consumed, closed := feed(t, s, st, strings.Repeat(req, 10))
	if closed || !st.blocked || len(resps) == 0 || len(resps) == 10 || consumed != len(resps)*len(req) {
		t.Fatalf("%d responses, consumed %d, blocked %v, closed %v", len(resps), consumed, st.blocked, closed)
	}
}

func TestStreamHandler(t *testing.T) {
	var got bytes.Buffer
	var path string
	ended := 0
	s := &Server{
		Handler:      testHandler(),
		MaxBodyBytes: 16,
		StreamHandler: func(c *Ctx) {
			if string(c.Path) == "/refuse" {
				c.Text(403, "no")
				return
			}
			path = string(c.Path)
			c.ReceiveBody(&BodyStream{
				Data: func(c *Ctx, p []byte) error {
					if bytes.Contains(p, []byte("!")) {
						return errors.New("bad byte")
					}
					got.Write(p)
					return nil
				},
				End: func(c *Ctx) { ended++; c.Text(200, fmt.Sprintf("%s %d", path, got.Len())) },
			})
		},
	}
	st := s.getState()
	body := strings.Repeat("x", 100)
	head := "POST /up HTTP/1.1\r\nHost: h\r\nContent-Length: 100\r\n\r\n"

	// The body arrives in three pieces, then a pipelined request.
	req := head + body + "GET /users/5 HTTP/1.1\r\nHost: h\r\n\r\n"
	off := 0
	var bodies []string
	for _, end := range []int{len(head) + 10, len(head) + 60, len(req)} {
		_, b, consumed, closed := feed(t, s, st, req[off:end])
		if closed {
			t.Fatalf("closed at %d", end)
		}
		off += consumed
		bodies = append(bodies, b...)
	}
	if off != len(req) || ended != 1 || got.String() != body || strings.Join(bodies, ",") != "/up 100,5" {
		t.Fatalf("consumed %d of %d, ended %d, got %d bytes, bodies %q", off, len(req), ended, got.Len(), bodies)
	}

	// Refused: the response, then close.
	resps, _, _, closed := feed(t, s, st, "POST /refuse HTTP/1.1\r\nHost: h\r\nContent-Length: 100\r\n\r\n")
	if len(resps) != 1 || resps[0].StatusCode != 403 || !closed {
		t.Fatalf("refused: %v closed %v", resps, closed)
	}

	// Data fails: 500 and close.
	st = s.getState()
	resps, _, _, closed = feed(t, s, st, head+"ab!")
	if len(resps) != 1 || resps[0].StatusCode != 500 || !closed {
		t.Fatalf("failing Data: %v closed %v", resps, closed)
	}

	// Without a StreamHandler: 413.
	s.StreamHandler = nil
	st = s.getState()
	resps, _, _, closed = feed(t, s, st, head)
	if len(resps) != 1 || resps[0].StatusCode != 413 || !closed {
		t.Fatalf("no StreamHandler: %v closed %v", resps, closed)
	}
}

// dial opens a raw connection to addr that fails the test after 10 s.
func dial(t *testing.T, addr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	return conn, bufio.NewReader(conn)
}

func readResponse(t *testing.T, br *bufio.Reader) (int, string) {
	t.Helper()
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(body)
}

func asyncHandler(release chan struct{}) Handler {
	r := NewRouter()
	r.GET("/slow/:ms", func(c *Ctx) {
		c.Async(func(c *Ctx) {
			d, _ := time.ParseDuration(string(c.Param("ms")) + "ms")
			time.Sleep(d)
			c.Text(200, "slow "+string(c.Param("ms")))
		})
	})
	r.GET("/wait", func(c *Ctx) {
		c.Async(func(c *Ctx) {
			<-release
			c.Text(200, "released")
		})
	})
	r.GET("/fast", func(c *Ctx) { c.Text(200, "fast") })
	r.GET("/apanic", func(c *Ctx) { c.Async(func(c *Ctx) { panic("boom") }) })
	r.GET("/asilent", func(c *Ctx) { c.Async(func(c *Ctx) {}) })
	return r.Serve
}

func TestAsync(t *testing.T) {
	addr := startServerWith(t, &Server{Handler: asyncHandler(nil)})
	conn, br := dial(t, addr)

	// Pipelined: the responses keep the order of the requests.
	fmt.Fprint(conn, "GET /slow/50 HTTP/1.1\r\nHost: h\r\n\r\nGET /fast HTTP/1.1\r\nHost: h\r\n\r\n"+
		"GET /slow/1 HTTP/1.1\r\nHost: h\r\n\r\nGET /asilent HTTP/1.1\r\nHost: h\r\n\r\nGET /fast HTTP/1.1\r\nHost: h\r\n\r\n")
	for _, want := range []string{"200 slow 50", "200 fast", "200 slow 1", "204 ", "200 fast"} {
		if status, body := readResponse(t, br); fmt.Sprint(status, " ", body) != want {
			t.Fatalf("got %d %q, want %s", status, body, want)
		}
	}

	// A panic is a 500 that closes the connection.
	fmt.Fprint(conn, "GET /apanic HTTP/1.1\r\nHost: h\r\n\r\n")
	if status, _ := readResponse(t, br); status != 500 {
		t.Fatalf("panic: %d", status)
	}
	if _, err := br.ReadByte(); err != io.EOF {
		t.Fatalf("after panic: %v", err)
	}
}

func TestAsyncLimit(t *testing.T) {
	release := make(chan struct{})
	addr := startServerWith(t, &Server{Handler: asyncHandler(release), MaxAsync: 1})
	defer close(release)

	c1, br1 := dial(t, addr)
	fmt.Fprint(c1, "GET /wait HTTP/1.1\r\nHost: h\r\n\r\n")
	time.Sleep(50 * time.Millisecond)

	c2, br2 := dial(t, addr)
	fmt.Fprint(c2, "GET /wait HTTP/1.1\r\nHost: h\r\n\r\n")
	if status, _ := readResponse(t, br2); status != 503 {
		t.Fatalf("over the limit: %d", status)
	}
	release <- struct{}{}
	if status, body := readResponse(t, br1); status != 200 || body != "released" {
		t.Fatalf("got %d %q", status, body)
	}
}

func TestTimeouts(t *testing.T) {
	s := &Server{
		Handler:           testHandler(),
		ReadHeaderTimeout: 100 * time.Millisecond,
		ReadTimeout:       300 * time.Millisecond,
		IdleTimeout:       200 * time.Millisecond,
	}
	addr := startServerWith(t, s)

	elapsed := func(f func()) time.Duration {
		start := time.Now()
		f()
		return time.Since(start)
	}

	// Idle: closed without a response.
	conn, br := dial(t, addr)
	fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: h\r\n\r\n")
	readResponse(t, br)
	if d := elapsed(func() {
		if _, err := br.ReadByte(); err != io.EOF {
			t.Errorf("idle: %v", err)
		}
	}); d < 150*time.Millisecond || d > 2*time.Second {
		t.Errorf("idle close after %v", d)
	}

	// Slowloris: a header that never ends gets a 408.
	conn, br = dial(t, addr)
	fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: h\r\n")
	go func(conn net.Conn) {
		for i := 0; i < 20; i++ {
			time.Sleep(20 * time.Millisecond)
			if _, err := fmt.Fprint(conn, "X: y\r\n"); err != nil {
				return
			}
		}
	}(conn)
	if d := elapsed(func() {
		if status, _ := readResponse(t, br); status != 408 {
			t.Errorf("header timeout: %d", status)
		}
	}); d < 80*time.Millisecond || d > 2*time.Second {
		t.Errorf("header timeout after %v", d)
	}

	// A body that never ends: the header was in time, the body is not.
	conn, br = dial(t, addr)
	fmt.Fprint(conn, "POST /echo HTTP/1.1\r\nHost: h\r\nContent-Length: 10\r\n\r\nab")
	if d := elapsed(func() {
		if status, _ := readResponse(t, br); status != 408 {
			t.Errorf("read timeout: %d", status)
		}
	}); d < 250*time.Millisecond || d > 2*time.Second {
		t.Errorf("read timeout after %v", d)
	}
}

func TestWriteTimeout(t *testing.T) {
	big := strings.Repeat("x", 1<<20)
	r := NewRouter()
	r.GET("/big", func(c *Ctx) { c.Text(200, big) })
	s := &Server{Handler: r.Serve, MaxOutboundBytes: 1 << 20, WriteTimeout: 200 * time.Millisecond}
	addr := startServerWith(t, s)

	// A client that pipelines requests and never reads: once the responses
	// pile up the connection is closed.
	conn, _ := dial(t, addr)
	conn.(*net.TCPConn).SetReadBuffer(4096)
	go func() {
		for i := 0; i < 64; i++ {
			if _, err := fmt.Fprint(conn, "GET /big HTTP/1.1\r\nHost: h\r\n\r\n"); err != nil {
				return
			}
		}
	}()
	time.Sleep(time.Second)
	var closed atomic.Bool
	go func() {
		_, err := io.Copy(io.Discard, conn)
		closed.Store(err == nil)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for !closed.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !closed.Load() {
		t.Fatal("the connection of a client that does not read stays open")
	}
}

func TestShutdownWaitsForRequests(t *testing.T) {
	release := make(chan struct{})
	s := &Server{Handler: asyncHandler(release)}
	addr, done := runServer(t, s)

	busy, br := dial(t, addr)
	fmt.Fprint(busy, "GET /wait HTTP/1.1\r\nHost: h\r\n\r\n")
	idle, idleBr := dial(t, addr)
	fmt.Fprint(idle, "GET /fast HTTP/1.1\r\nHost: h\r\n\r\n")
	readResponse(t, idleBr)
	time.Sleep(50 * time.Millisecond)

	shut := make(chan error, 1)
	go func() { shut <- s.Shutdown(context.Background()) }()

	// The idle connection is closed at once, the busy one is waited for.
	if _, err := idleBr.ReadByte(); err != io.EOF {
		t.Fatalf("idle connection: %v", err)
	}
	select {
	case err := <-shut:
		t.Fatalf("Shutdown returned with a request in flight: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	// No new connection.
	if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Read(make([]byte, 1)); err == nil {
			t.Error("a new connection is served during Shutdown")
		}
		c.Close()
	}

	close(release)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || !resp.Close {
		t.Fatalf("in-flight response: %d %v", resp.StatusCode, resp.Header)
	}
	if err := <-shut; err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("ListenAndServe: %v", err)
	}
}

func TestShutdownDeadline(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	s := &Server{Handler: asyncHandler(release)}
	addr, done := runServer(t, s)
	busy, _ := dial(t, addr)
	fmt.Fprint(busy, "GET /wait HTTP/1.1\r\nHost: h\r\n\r\n")
	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := s.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("ListenAndServe: %v", err)
	}
}

// testCert returns a self-signed certificate for 127.0.0.1.
func testCert(t testing.TB) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "wisp test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startTLS serves s over TLS until the end of the test.
func startTLS(t *testing.T, s *Server) string {
	t.Helper()
	ln, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.ServeTLS(ln, &tls.Config{Certificates: []tls.Certificate{testCert(t)}}) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.Shutdown(ctx); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
		if err := <-done; err != nil {
			t.Errorf("ServeTLS: %v", err)
		}
	})
	return ln.Addr().String()
}

func TestTLS(t *testing.T) {
	r := NewRouter()
	r.GET("/", func(c *Ctx) { c.Text(200, fmt.Sprintf("tls=%v", c.IsTLS())) })
	r.POST("/echo", func(c *Ctx) { c.Bytes(200, MIMEOctetStream, c.Body) })
	r.GET("/slow", func(c *Ctx) {
		c.Async(func(c *Ctx) { time.Sleep(20 * time.Millisecond); c.Text(200, "slow") })
	})
	addr := startTLS(t, &Server{Handler: r.Serve})

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	defer client.CloseIdleConnections()
	for i := 0; i < 20; i++ {
		resp, err := client.Get("https://" + addr + "/")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || string(body) != "tls=true" || resp.TLS == nil {
			t.Fatalf("GET: %d %q", resp.StatusCode, body)
		}
	}

	payload := bytes.Repeat([]byte("0123456789abcdef"), 1<<16)
	resp, err := client.Post("https://"+addr+"/echo", MIMEOctetStream, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	echoed, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.Equal(echoed, payload) {
		t.Fatalf("echo: %d, %d bytes", resp.StatusCode, len(echoed))
	}

	// Pipelined, with an Async request in the middle.
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprint(conn, "GET /slow HTTP/1.1\r\nHost: h\r\n\r\nGET / HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n")
	br := bufio.NewReader(conn)
	for _, want := range []string{"slow", "tls=true"} {
		if status, body := readResponse(t, br); status != 200 || body != want {
			t.Fatalf("pipelined: %d %q, want %q", status, body, want)
		}
	}
	if _, err := br.ReadByte(); err != io.EOF {
		t.Fatalf("after Connection: close: %v", err)
	}
}

func TestTLSALPN(t *testing.T) {
	addr := startTLS(t, &Server{Handler: testHandler()})
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if p := conn.ConnectionState().NegotiatedProtocol; p != "http/1.1" {
		t.Fatalf("ALPN: %q", p)
	}
}

func TestTLSHandshakeTimeout(t *testing.T) {
	addr := startTLS(t, &Server{Handler: testHandler(), ReadHeaderTimeout: 100 * time.Millisecond})
	conn, _ := dial(t, addr)
	start := time.Now()
	if _, err := conn.Read(make([]byte, 1)); err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("a connection without handshake: %v after %v", err, time.Since(start))
	}
}

func TestTLSWebSocket(t *testing.T) {
	h := &WSHandler{OnMessage: func(ws *WSConn, typ WSMessageType, data []byte) { ws.Send(typ, data) }}
	addr := startTLS(t, &Server{Handler: upgradeHandler(h)})
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprint(conn, wsRequest("/"))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 101 {
		t.Fatalf("handshake: %v %v", resp, err)
	}
	conn.Write(clientFrame(true, opText, []byte("over tls")))
	f, err := readServerFrame(br)
	if err != nil || f.op != opText || string(f.payload) != "over tls" {
		t.Fatalf("echo: %+v %v", f, err)
	}
}

var dateLine = regexp.MustCompile(`Date: [^\r]*\r\n`)

// runSplit serves input as httpTraffic would if it arrived in pieces cut at
// the given offsets, and returns everything written, without the Date
// headers and the "100 Continue" responses, which depend on the cuts.
func runSplit(s *Server, input []byte, cuts []int) (string, bool) {
	st := s.getState()
	defer s.putState(st)
	var out, buf []byte
	prev := 0
	for _, cut := range append(cuts, len(input)) {
		if cut <= prev || cut > len(input) {
			continue
		}
		buf = append(buf, input[prev:cut]...)
		prev = cut
		if st.need > 0 && len(buf) < st.need {
			continue
		}
		st.need = 0
		st.ctx.out = st.ctx.out[:0]
		consumed, closed := s.process(st, buf)
		out = append(out, st.ctx.out...)
		buf = buf[consumed:]
		if closed {
			return strings.ReplaceAll(dateLine.ReplaceAllString(string(out), ""), string(continueResponse), ""), true
		}
	}
	return strings.ReplaceAll(dateLine.ReplaceAllString(string(out), ""), string(continueResponse), ""), false
}

func FuzzProcess(f *testing.F) {
	for _, seed := range []string{
		"GET / HTTP/1.1\r\nHost: h\r\n\r\n",
		"GET /users/42?a=1 HTTP/1.1\r\nHost: h\r\n\r\nGET /q?a=%41+b HTTP/1.1\r\nHost: h\r\n\r\n",
		"POST /echo HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello",
		"POST /echo HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX: y\r\n\r\n",
		"POST /form HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 7\r\n\r\na=1&b=2",
		"POST /echo HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\nok",
		"GET http://example.com/caf%C3%A9 HTTP/1.1\r\nHost: h\r\n\r\n",
		"OPTIONS * HTTP/1.1\r\nHost: h\r\n\r\n",
		"HEAD /users/1 HTTP/1.0\r\nConnection: keep-alive\r\n\r\n",
		"GET /users/ HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\nGET / HTTP/1.1\r\n\r\n",
	} {
		f.Add([]byte(seed), uint16(7), uint16(30))
	}

	r := NewRouter()
	r.GET("/", func(c *Ctx) { c.Text(200, "root") })
	r.GET("/users/:id", func(c *Ctx) { c.Bytes(200, MIMETextPlain, c.Param("id")) })
	r.GET("/q", func(c *Ctx) {
		var b []byte
		c.VisitQuery(func(k, v []byte) bool { b = append(append(append(b, k...), '='), v...); return true })
		c.Bytes(200, MIMETextPlain, b)
	})
	r.POST("/echo", func(c *Ctx) { c.Bytes(200, MIMEOctetStream, c.Body) })
	r.POST("/form", func(c *Ctx) { c.Bytes(200, MIMETextPlain, c.FormParam("a")) })
	r.Handle("OPTIONS", "/", func(c *Ctx) { c.Status(204) })
	fallback := r.Serve
	handler := func(c *Ctx) {
		if string(c.Path) != "*" && !bytes.HasPrefix(c.Path, slash) {
			panic("path " + string(c.Path))
		}
		fallback(c)
	}
	s := &Server{Handler: handler, MaxHeaderBytes: 512, MaxBodyBytes: 256}

	f.Fuzz(func(t *testing.T, input []byte, a, b uint16) {
		whole, wholeClosed := runSplit(s, input, nil)
		cuts := []int{int(a) % (len(input) + 1), int(b) % (len(input) + 1)}
		if cuts[0] > cuts[1] {
			cuts[0], cuts[1] = cuts[1], cuts[0]
		}
		split, splitClosed := runSplit(s, input, cuts)
		if whole != split || wholeClosed != splitClosed {
			t.Fatalf("cut at %v:\n%q (closed %v)\nwhole:\n%q (closed %v)", cuts, split, splitClosed, whole, wholeClosed)
		}
	})
}
