package httpd

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/panjf2000/gnet/v2"
)

// splitResponse returns the status and the body of the single response in raw.
func splitResponse(t *testing.T, raw []byte) (int, string) {
	t.Helper()

	head, body, ok := bytes.Cut(raw, []byte("\r\n\r\n"))
	if !ok || len(head) < len("HTTP/1.1 200") {
		t.Fatalf("not an HTTP response: %q", raw)
	}
	status, err := strconv.Atoi(string(head[9:12]))
	if err != nil {
		t.Fatalf("bad status line in %q", raw)
	}
	return status, string(body)
}

func testHandler() Handler {
	r := NewRouter()
	r.GET("/", func(c *Ctx) { c.Text(200, "Hello, World!") })
	r.GET("/users/:id", func(c *Ctx) { c.Bytes(200, "text/plain; charset=utf-8", c.Param("id")) })
	r.GET("/query", func(c *Ctx) { c.Bytes(200, "text/plain", c.Query) })
	r.GET("/agent", func(c *Ctx) { c.Bytes(200, "text/plain", c.Header("user-agent")) })
	r.POST("/echo", func(c *Ctx) { c.Bytes(200, "application/octet-stream", c.Body) })
	r.GET("/silent", func(c *Ctx) {})
	r.GET("/twice", func(c *Ctx) { c.Text(500, "first"); c.Text(200, "second") })
	r.GET("/header", func(c *Ctx) { c.SetHeader("X-Test", "yes"); c.Status(204) })
	r.GET("/panic", func(c *Ctx) { panic("boom") })
	return r.Serve
}

// feed runs process-with-recovery on input the way OnTraffic does and parses
// what was written.
func feed(t testing.TB, s *Server, st *connState, input string) (resps []*http.Response, bodies []string, consumed int, closed bool) {
	t.Helper()

	st.ctx.out = st.ctx.out[:0]
	consumed, closed = s.serve(st, []byte(input))

	br := bufio.NewReader(bytes.NewReader(st.ctx.out))
	for {
		if _, err := br.Peek(1); err == io.EOF {
			break
		}
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("invalid response in %q: %v", st.ctx.out, err)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("invalid response body in %q: %v", st.ctx.out, err)
		}
		resps = append(resps, resp)
		bodies = append(bodies, string(body))
	}
	return resps, bodies, consumed, closed
}

func newTestState(t *testing.T) (*Server, *connState) {
	s := &Server{Handler: testHandler()}
	return s, s.getState()
}

func TestProcessSimpleGet(t *testing.T) {
	s, st := newTestState(t)

	req := "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
	resps, bodies, consumed, closed := feed(t, s, st, req)

	if len(resps) != 1 || resps[0].StatusCode != 200 || bodies[0] != "Hello, World!" {
		t.Fatalf("got %d responses %q", len(resps), bodies)
	}
	if consumed != len(req) || closed {
		t.Errorf("consumed = %d (want %d), closed = %v", consumed, len(req), closed)
	}

	h := resps[0].Header
	if h.Get("Content-Type") != "text/plain; charset=utf-8" || h.Get("Content-Length") != "13" || h.Get("Server") != "wisp" {
		t.Errorf("unexpected headers: %v", h)
	}
	if _, err := http.ParseTime(h.Get("Date")); err != nil {
		t.Errorf("bad Date header %q", h.Get("Date"))
	}
}

func TestProcessRequestData(t *testing.T) {
	s, st := newTestState(t)

	tests := []struct{ req, want string }{
		{"GET /users/42 HTTP/1.1\r\n\r\n", "42"},
		{"GET /users/42?full=1 HTTP/1.1\r\n\r\n", "42"},
		{"GET /query?a=1&b=2 HTTP/1.1\r\n\r\n", "a=1&b=2"},
		{"GET /query HTTP/1.1\r\n\r\n", ""},
		{"GET /agent HTTP/1.1\r\nUser-Agent: test/1.0\r\n\r\n", "test/1.0"},
		{"POST /echo HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello", "hello"},
		{"POST /echo HTTP/1.1\r\nContent-Length: 0\r\n\r\n", ""},
		{"POST /echo HTTP/1.1\r\n\r\n", ""},
	}
	for _, tt := range tests {
		resps, bodies, consumed, closed := feed(t, s, st, tt.req)
		if len(resps) != 1 || resps[0].StatusCode != 200 || bodies[0] != tt.want {
			t.Errorf("%q: got %q, want one 200 with %q", tt.req, st.ctx.out, tt.want)
		}
		if consumed != len(tt.req) || closed {
			t.Errorf("%q: consumed = %d, closed = %v", tt.req, consumed, closed)
		}
	}
}

func TestProcessPipelining(t *testing.T) {
	s, st := newTestState(t)

	// Three whole requests and the beginning of a fourth.
	whole := "GET /users/1 HTTP/1.1\r\n\r\n" +
		"POST /echo HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc" +
		"GET /users/3 HTTP/1.1\r\n\r\n"
	_, bodies, consumed, closed := feed(t, s, st, whole+"GET /users/4 HT")

	if got := strings.Join(bodies, ","); got != "1,abc,3" {
		t.Errorf("bodies = %q, want 1,abc,3", got)
	}
	if consumed != len(whole) || closed {
		t.Errorf("consumed = %d (want %d), closed = %v", consumed, len(whole), closed)
	}
}

func TestProcessIncompleteRequest(t *testing.T) {
	s, st := newTestState(t)

	req := "POST /echo HTTP/1.1\r\nContent-Length: 10\r\n\r\n0123456789"

	// Whatever the cut point, nothing is consumed or answered before the
	// request is whole.
	for i := 1; i < len(req); i++ {
		st.need = 0
		resps, _, consumed, closed := feed(t, s, st, req[:i])
		if len(resps) != 0 || consumed != 0 || closed {
			t.Fatalf("prefix of %d bytes: %d responses, consumed = %d, closed = %v", i, len(resps), consumed, closed)
		}
	}

	// Once the headers are in, the state remembers how much is still missing.
	if st.need != len(req) {
		t.Errorf("need = %d, want %d", st.need, len(req))
	}

	_, bodies, consumed, _ := feed(t, s, st, req)
	if len(bodies) != 1 || bodies[0] != "0123456789" || consumed != len(req) {
		t.Errorf("whole request: bodies = %q, consumed = %d", bodies, consumed)
	}
}

func TestProcessConnectionHandling(t *testing.T) {
	s, st := newTestState(t)

	tests := []struct {
		req    string
		closed bool
	}{
		{"GET / HTTP/1.1\r\n\r\n", false},
		{"GET / HTTP/1.1\r\nConnection: close\r\n\r\n", true},
		{"GET / HTTP/1.1\r\nConnection: Keep-Alive, Close\r\n\r\n", true},
		{"GET / HTTP/1.1\r\nconnection: keep-alive\r\n\r\n", false},
		{"GET / HTTP/1.0\r\n\r\n", true},
		{"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n", false},
	}
	for _, tt := range tests {
		resps, _, _, closed := feed(t, s, st, tt.req)
		if closed != tt.closed {
			t.Errorf("%q: closed = %v, want %v", tt.req, closed, tt.closed)
		}
		// http.ReadResponse turns the "Connection: close" header into Close.
		if resps[0].Close != tt.closed {
			t.Errorf("%q: Connection: close header present = %v, want %v", tt.req, resps[0].Close, tt.closed)
		}
	}

	// Nothing after a request that closes the connection is served.
	_, bodies, _, _ := feed(t, s, st, "GET /users/1 HTTP/1.1\r\nConnection: close\r\n\r\nGET /users/2 HTTP/1.1\r\n\r\n")
	if len(bodies) != 1 || bodies[0] != "1" {
		t.Errorf("bodies = %q, want only the first response", bodies)
	}
}

func TestProcessRejects(t *testing.T) {
	s, st := newTestState(t)
	s.MaxHeaderBytes = 256
	s.MaxBodyBytes = 1024

	tests := []struct {
		name, req string
		status    int
	}{
		{"garbage", "\x16\x03\x01\x02\x00\r\n\r\n", 400},
		{"no colon", "GET / HTTP/1.1\r\nNope\r\n\r\n", 400},
		{"http/2 preface", "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 505},
		{"bad content-length", "POST /echo HTTP/1.1\r\nContent-Length: abc\r\n\r\n", 400},
		{"negative content-length", "POST /echo HTTP/1.1\r\nContent-Length: -1\r\n\r\n", 400},
		{"conflicting content-length", "POST /echo HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab", 400},
		{"chunked", "POST /echo HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", 501},
		{"body too large", "POST /echo HTTP/1.1\r\nContent-Length: 1025\r\n\r\n", 413},
		{"headers too large", "GET / HTTP/1.1\r\nX: " + strings.Repeat("a", 300) + "\r\n\r\n", 431},
		{"headers too large, incomplete", "GET / HTTP/1.1\r\nX: " + strings.Repeat("a", 300), 431},
	}
	for _, tt := range tests {
		resps, _, _, closed := feed(t, s, st, tt.req)
		if len(resps) != 1 || resps[0].StatusCode != tt.status {
			t.Errorf("%s: got %q, want a %d", tt.name, st.ctx.out, tt.status)
			continue
		}
		if !closed || !resps[0].Close {
			t.Errorf("%s: the connection must be closed", tt.name)
		}
	}

	// Agreeing duplicates are harmless.
	resps, bodies, _, _ := feed(t, s, st, "POST /echo HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nab")
	if len(resps) != 1 || resps[0].StatusCode != 200 || bodies[0] != "ab" {
		t.Errorf("duplicate content-length: got %q", st.ctx.out)
	}
}

func TestProcessResponses(t *testing.T) {
	s, st := newTestState(t)

	resps, bodies, _, _ := feed(t, s, st, "GET /silent HTTP/1.1\r\n\r\n")
	if resps[0].StatusCode != 204 || bodies[0] != "" || resps[0].Header.Get("Content-Length") != "" {
		t.Errorf("handler without response: got %q, want a bare 204", st.ctx.out)
	}

	resps, bodies, _, _ = feed(t, s, st, "GET /twice HTTP/1.1\r\n\r\n")
	if len(resps) != 1 || resps[0].StatusCode != 200 || bodies[0] != "second" {
		t.Errorf("second response must replace the first: got %q", st.ctx.out)
	}

	resps, _, _, _ = feed(t, s, st, "GET /header HTTP/1.1\r\n\r\n")
	if resps[0].StatusCode != 204 || resps[0].Header.Get("X-Test") != "yes" {
		t.Errorf("SetHeader: got %q", st.ctx.out)
	}

	// HEAD falls back to the GET route: same headers, no body.
	st.ctx.out = st.ctx.out[:0]
	s.serve(st, []byte("HEAD /users/12345 HTTP/1.1\r\n\r\n"))
	if out := string(st.ctx.out); !strings.Contains(out, "Content-Length: 5\r\n") || !strings.HasSuffix(out, "\r\n\r\n") {
		t.Errorf("HEAD: got %q", out)
	}
}

func TestProcessExpectContinue(t *testing.T) {
	s, st := newTestState(t)

	head := "POST /echo HTTP/1.1\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\n"

	st.ctx.out = st.ctx.out[:0]
	consumed, _ := s.serve(st, []byte(head))
	if string(st.ctx.out) != "HTTP/1.1 100 Continue\r\n\r\n" || consumed != 0 {
		t.Fatalf("headers only: out = %q, consumed = %d", st.ctx.out, consumed)
	}

	// More data that still does not complete the body: no second 100.
	st.ctx.out = st.ctx.out[:0]
	s.serve(st, []byte(head+"da"))
	if len(st.ctx.out) != 0 {
		t.Fatalf("partial body: out = %q, want nothing", st.ctx.out)
	}

	_, bodies, consumed, _ := feed(t, s, st, head+"data")
	if len(bodies) != 1 || bodies[0] != "data" || consumed != len(head)+4 {
		t.Errorf("whole request: bodies = %q, consumed = %d", bodies, consumed)
	}
}

func TestProcessRecoversPanic(t *testing.T) {
	s, st := newTestState(t)

	log.SetOutput(io.Discard)
	defer log.SetOutput(log.Writer())

	resps, bodies, _, closed := feed(t, s, st, "GET /users/1 HTTP/1.1\r\n\r\nGET /panic HTTP/1.1\r\n\r\n")
	if len(resps) != 2 || bodies[0] != "1" || resps[1].StatusCode != 500 || !closed {
		t.Errorf("got %q, closed = %v; want the first response, then a 500 and a close", st.ctx.out, closed)
	}
}

func TestProcessDoesNotAllocate(t *testing.T) {
	s, st := newTestState(t)

	for _, req := range []string{
		"GET / HTTP/1.1\r\nUser-Agent: fasthttp\r\nHost: 127.0.0.1:8080\r\n\r\n",
		"GET /users/42 HTTP/1.1\r\nUser-Agent: fasthttp\r\nHost: 127.0.0.1:8080\r\n\r\n",
		"POST /echo HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Length: 5\r\n\r\nhello",
	} {
		buf := []byte(req)
		allocs := testing.AllocsPerRun(200, func() {
			st.ctx.out = st.ctx.out[:0]
			if consumed, _ := s.serve(st, buf); consumed != len(buf) {
				t.Fatalf("consumed = %d, want %d", consumed, len(buf))
			}
		})
		if allocs != 0 {
			t.Errorf("%q: %v allocs per request, want 0", req, allocs)
		}
	}
}

func BenchmarkProcess(b *testing.B) {
	for _, bm := range []struct{ name, req string }{
		{"static", "GET / HTTP/1.1\r\nUser-Agent: fasthttp\r\nHost: 127.0.0.1:8080\r\n\r\n"},
		{"param", "GET /users/42 HTTP/1.1\r\nUser-Agent: fasthttp\r\nHost: 127.0.0.1:8080\r\n\r\n"},
	} {
		b.Run(bm.name, func(b *testing.B) {
			s := &Server{Handler: testHandler()}
			st := s.getState()
			buf := []byte(bm.req)

			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				st.ctx.out = st.ctx.out[:0]
				s.serve(st, buf)
			}
		})
	}
}

// The tests below go through gnet and a real socket.

func startServer(t *testing.T) string {
	t.Helper()
	return startServerWith(t, &Server{Handler: testHandler()})
}

// startServerWith runs s until the end of the test.
func startServerWith(t *testing.T, s *Server) string {
	t.Helper()
	addr, done := runServer(t, s)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.Shutdown(ctx); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
		if err := <-done; err != nil {
			t.Errorf("ListenAndServe: %v", err)
		}
	})
	return addr
}

// runServer starts s with two event loops and waits until it accepts
// connections; done receives what ListenAndServe returns.
func runServer(t *testing.T, s *Server) (addr string, done chan error) {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr = l.Addr().String()
	l.Close()

	done = make(chan error, 1)
	go func() {
		done <- s.ListenAndServe(addr, gnet.WithNumEventLoop(2))
	}()

	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			conn.Close()
			break
		}
		select {
		case err := <-done:
			t.Fatalf("server stopped: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("server not reachable on %s: %v", addr, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return addr, done
}

func TestServerWithHTTPClient(t *testing.T) {
	addr := startServer(t)
	client := &http.Client{Timeout: 10 * time.Second}

	get := func(path string) (int, string) {
		t.Helper()
		resp, err := client.Get("http://" + addr + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, string(body)
	}

	// Sequential requests reuse one keep-alive connection.
	for i := 0; i < 50; i++ {
		id := strconv.Itoa(i)
		if status, body := get("/users/" + id); status != 200 || body != id {
			t.Fatalf("GET /users/%s: %d %q", id, status, body)
		}
	}
	if status, body := get("/"); status != 200 || body != "Hello, World!" {
		t.Errorf("GET /: %d %q", status, body)
	}
	if status, _ := get("/nope"); status != 404 {
		t.Errorf("GET /nope: %d, want 404", status)
	}

	// A body much larger than gnet's 64 KiB read buffer arrives over many
	// events and has to come back intact.
	payload := bytes.Repeat([]byte("0123456789abcdef"), 1<<16) // 1 MiB
	resp, err := client.Post("http://"+addr+"/echo", "application/octet-stream", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	echoed, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || !bytes.Equal(echoed, payload) {
		t.Errorf("POST /echo of %d bytes: status %d, %d bytes back", len(payload), resp.StatusCode, len(echoed))
	}
}

func TestServerRawConnection(t *testing.T) {
	addr := startServer(t)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(conn)

	read := func() (int, string) {
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

	// A request trickling in one piece per TCP segment.
	for _, piece := range []string{"GET /us", "ers/7 HTTP/1.1\r\nHo", "st: x\r\n", "\r\n"} {
		fmt.Fprint(conn, piece)
		time.Sleep(20 * time.Millisecond)
	}
	if status, body := read(); status != 200 || body != "7" {
		t.Fatalf("split request: %d %q", status, body)
	}

	// A body arriving after its headers.
	fmt.Fprint(conn, "POST /echo HTTP/1.1\r\nContent-Length: 11\r\n\r\nhello")
	time.Sleep(20 * time.Millisecond)
	fmt.Fprint(conn, " world")
	if status, body := read(); status != 200 || body != "hello world" {
		t.Fatalf("split body: %d %q", status, body)
	}

	// Pipelined requests are answered in order, the last one cut in two.
	fmt.Fprint(conn, "GET /users/1 HTTP/1.1\r\n\r\nGET /users/2 HTTP/1.1\r\n\r\nGET /users/3 HT")
	time.Sleep(20 * time.Millisecond)
	fmt.Fprint(conn, "TP/1.1\r\n\r\n")
	for _, want := range []string{"1", "2", "3"} {
		if status, body := read(); status != 200 || body != want {
			t.Fatalf("pipelining: %d %q, want 200 %q", status, body, want)
		}
	}

	// Connection: close is honoured: the response, then EOF.
	fmt.Fprint(conn, "GET / HTTP/1.1\r\nConnection: close\r\n\r\n")
	if status, body := read(); status != 200 || body != "Hello, World!" {
		t.Fatalf("connection close: %d %q", status, body)
	}
	if _, err := br.ReadByte(); err != io.EOF {
		t.Errorf("after Connection: close: err = %v, want EOF", err)
	}
}

func TestServerClosesOnBadRequest(t *testing.T) {
	addr := startServer(t)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	fmt.Fprint(conn, "NOT HTTP\r\n\r\n")

	raw, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := splitResponse(t, raw); status != 400 {
		t.Errorf("got %q, want a 400", raw)
	}
}
