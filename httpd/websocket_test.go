package httpd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

// The client side of the protocol, written by hand so that the tests can
// also send what a correct client never would.

const testWSKey = "dGhlIHNhbXBsZSBub25jZQ==" // the example of RFC 6455, section 1.3

// wsRequest is an opening handshake; extra lines are added, and a line
// "-Name" removes the header Name.
func wsRequest(path string, lines ...string) string {
	headers := []string{
		"Host: example.com",
		"Upgrade: websocket",
		"Connection: Upgrade",
		"Sec-WebSocket-Key: " + testWSKey,
		"Sec-WebSocket-Version: 13",
	}
	for _, l := range lines {
		if name, ok := strings.CutPrefix(l, "-"); ok {
			for i, h := range headers {
				if strings.HasPrefix(h, name+":") {
					headers = append(headers[:i], headers[i+1:]...)
					break
				}
			}
			continue
		}
		headers = append(headers, l)
	}
	return "GET " + path + " HTTP/1.1\r\n" + strings.Join(headers, "\r\n") + "\r\n\r\n"
}

// rawFrame builds a frame with the first byte as given (FIN, RSV, opcode),
// masked with a random key unless masked is false.
func rawFrame(b0 byte, payload []byte, masked bool) []byte {
	b := appendFrameHeader(nil, 0, len(payload))
	b[0] = b0
	if !masked {
		return append(b, payload...)
	}
	b[1] |= 0x80
	var key [4]byte
	binary.LittleEndian.PutUint32(key[:], rand.Uint32())
	b = append(b, key[:]...)
	start := len(b)
	b = append(b, payload...)
	unmask(b[start:], key[:]) // masking and unmasking are the same XOR
	return b
}

func clientFrame(fin bool, op byte, payload []byte) []byte {
	b0 := op
	if fin {
		b0 |= 0x80
	}
	return rawFrame(b0, payload, true)
}

func closePayload(code int, reason string) []byte {
	return appendClosePayload(nil, code, reason)
}

type wsFrame struct {
	fin     bool
	op      byte
	payload []byte
}

// readServerFrame reads one frame as the server writes it: unmasked.
func readServerFrame(r io.Reader) (wsFrame, error) {
	var h [10]byte
	if _, err := io.ReadFull(r, h[:2]); err != nil {
		return wsFrame{}, err
	}
	if h[1]&0x80 != 0 {
		return wsFrame{}, errors.New("server frame is masked")
	}
	if h[0]&0x70 != 0 {
		return wsFrame{}, errors.New("server frame has RSV bits")
	}
	n := uint64(h[1] & 0x7F)
	switch n {
	case 126:
		if _, err := io.ReadFull(r, h[2:4]); err != nil {
			return wsFrame{}, err
		}
		n = uint64(binary.BigEndian.Uint16(h[2:]))
	case 127:
		if _, err := io.ReadFull(r, h[2:10]); err != nil {
			return wsFrame{}, err
		}
		n = binary.BigEndian.Uint64(h[2:])
	}
	f := wsFrame{fin: h[0]&0x80 != 0, op: h[0] & 0x0F, payload: make([]byte, n)}
	_, err := io.ReadFull(r, f.payload)
	return f, err
}

func serverFrames(t testing.TB, b []byte) []wsFrame {
	t.Helper()
	var frames []wsFrame
	r := bytes.NewReader(b)
	for r.Len() > 0 {
		f, err := readServerFrame(r)
		if err != nil {
			t.Fatalf("invalid server output %q: %v", b, err)
		}
		frames = append(frames, f)
	}
	return frames
}

func TestWSAcceptKey(t *testing.T) {
	var got [28]byte
	wsAcceptKey(&got, []byte(testWSKey))
	if string(got[:]) != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatalf("got %s", got)
	}
}

func TestWSValidKey(t *testing.T) {
	for key, want := range map[string]bool{
		testWSKey:                  true,
		"AAAAAAAAAAAAAAAAAAAAAA==": true,
		"":                         false,
		"dGhlIHNhbXBsZSBub25jZQ":   false, // no padding
		"dGhlIHNhbXBsZSBub25jZQ!=": false,
		"dGhlIHNhbXBsZSBub25jZWU=": false, // 17 bytes
		"dGhlIHNhbXBsZSBub25j":     false,
	} {
		if got := validWSKey([]byte(key)); got != want {
			t.Errorf("validWSKey(%q) = %v", key, got)
		}
	}
}

func TestUnmask(t *testing.T) {
	key := []byte{0x12, 0x34, 0x56, 0x78}
	for n := 0; n < 40; n++ {
		p := make([]byte, n)
		for i := range p {
			p[i] = byte(i * 7)
		}
		got := bytes.Clone(p)
		unmask(got, key)
		for i := range p {
			if got[i] != p[i]^key[i%4] {
				t.Fatalf("len %d, byte %d: got %x, want %x", n, i, got[i], p[i]^key[i%4])
			}
		}
	}
}

func TestAppendFrameHeader(t *testing.T) {
	for _, n := range []int{0, 1, 125, 126, 127, 65535, 65536, 1 << 20} {
		b := appendFrameHeader(nil, opBinary, n)
		b = append(b, make([]byte, n)...)
		f, err := readServerFrame(bytes.NewReader(b))
		if err != nil || !f.fin || f.op != opBinary || len(f.payload) != n {
			t.Fatalf("n=%d: %+v %v", n, f, err)
		}
	}
}

// utf8Feed must agree with utf8.Valid, wherever the input is split.
func TestUTF8Feed(t *testing.T) {
	cases := []string{
		"", "hello", "κόσμε", "\u0080", "߿", "ࠀ", "￿", "\U00010000", "\U0010ffff",
		"\xed\x9f\xbf", "\xee\x80\x80", "\xef\xbf\xbd",
		"\xc0\xaf", "\xc1\xbf", "\xe0\x80\xaf", "\xe0\x9f\xbf", "\xed\xa0\x80", "\xed\xbf\xbf",
		"\xf0\x80\x80\xaf", "\xf0\x8f\xbf\xbf", "\xf4\x90\x80\x80", "\xf5\x80\x80\x80", "\xff",
		"\xce\xba\xe1\xbd\xb9\xcf\x83\xce\xbc\xce\xb5\xed\xa0\x80edited",
		"\x80", "\xbf", "\xc2", "\xe0\xa0", "\xf0\x90\x80",
	}
	rng := rand.New(rand.NewSource(1))
	for range 20000 {
		b := make([]byte, rng.Intn(12))
		for i := range b {
			// Mostly bytes around the interesting boundaries.
			b[i] = []byte{0x00, 0x7f, 0x80, 0x8f, 0x90, 0x9f, 0xa0, 0xbf, 0xc0, 0xc2, 0xdf, 0xe0, 0xe1, 0xed, 0xef, 0xf0, 0xf1, 0xf4, 0xf5, 0xff}[rng.Intn(20)]
		}
		cases = append(cases, string(b))
	}

	for _, c := range cases {
		want := utf8.ValidString(c)
		for split := 0; split <= len(c); split++ {
			s := utf8Feed(utf8Feed(utf8Accept, []byte(c[:split])), []byte(c[split:]))
			if got := s == utf8Accept; got != want {
				t.Fatalf("%q split at %d: valid=%v, want %v", c, split, got, want)
			}
		}
	}
}

// Handshakes, through process like the HTTP tests.

func upgradeHandler(h *WSHandler) Handler {
	return func(c *Ctx) {
		c.Upgrade(h)
	}
}

func TestWSHandshake(t *testing.T) {
	h := &WSHandler{Subprotocols: []string{"v2.chat", "v1.chat"}}
	for _, tc := range []struct {
		name    string
		request string
		status  int
		header  string // "Name: value" expected in the response
	}{
		{"valid", wsRequest("/"), 101, "Sec-Websocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="},
		{"case-insensitive tokens", wsRequest("/", "-Upgrade", "-Connection", "Upgrade: WebSocket", "Connection: keep-alive, upgrade"), 101, ""},
		{"subprotocol by server preference", wsRequest("/", "Sec-WebSocket-Protocol: v1.chat, v2.chat"), 101, "Sec-Websocket-Protocol: v2.chat"},
		{"subprotocol in a second header", wsRequest("/", "Sec-WebSocket-Protocol: other", "Sec-WebSocket-Protocol: v1.chat"), 101, "Sec-Websocket-Protocol: v1.chat"},
		{"no common subprotocol", wsRequest("/", "Sec-WebSocket-Protocol: V2.CHAT"), 101, ""},
		{"same origin", wsRequest("/", "Origin: https://example.com"), 101, ""},
		{"cross origin", wsRequest("/", "Origin: https://evil.example"), 403, ""},
		{"origin null", wsRequest("/", "Origin: null"), 403, ""},
		{"no Upgrade", wsRequest("/", "-Upgrade"), 426, "Upgrade: websocket"},
		{"other Upgrade", wsRequest("/", "-Upgrade", "Upgrade: h2c"), 400, ""},
		{"no Connection: upgrade", wsRequest("/", "-Connection", "Connection: keep-alive"), 400, ""},
		{"no Host", wsRequest("/", "-Host"), 400, ""},
		{"old version", wsRequest("/", "-Sec-WebSocket-Version", "Sec-WebSocket-Version: 8"), 426, "Sec-Websocket-Version: 13"},
		{"no version", wsRequest("/", "-Sec-WebSocket-Version"), 426, "Sec-Websocket-Version: 13"},
		{"no key", wsRequest("/", "-Sec-WebSocket-Key"), 400, ""},
		{"bad key", wsRequest("/", "-Sec-WebSocket-Key", "Sec-WebSocket-Key: abc"), 400, ""},
		{"HTTP/1.0", strings.Replace(wsRequest("/"), "HTTP/1.1", "HTTP/1.0", 1), 400, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{Handler: upgradeHandler(h)}
			st := s.getState()
			resps, _, consumed, closed := feed(t, s, st, tc.request)
			if len(resps) != 1 || resps[0].StatusCode != tc.status {
				t.Fatalf("got %d responses %v, want status %d", len(resps), resps, tc.status)
			}
			// HTTP/1.0 without keep-alive closes after any response.
			if consumed != len(tc.request) || closed != strings.Contains(tc.request, "HTTP/1.0") {
				t.Fatalf("consumed %d of %d, closed %v", consumed, len(tc.request), closed)
			}
			if tc.header != "" {
				name, value, _ := strings.Cut(tc.header, ": ")
				if got := resps[0].Header.Get(name); got != value {
					t.Fatalf("%s: %q, want %q", name, got, value)
				}
			}
			if upgraded := st.ctx.ws != nil; upgraded != (tc.status == 101) {
				t.Fatalf("upgraded = %v", upgraded)
			}
			if tc.status == 101 && tc.header == "" && strings.Contains(tc.request, "V2.CHAT") {
				if p := resps[0].Header.Get("Sec-WebSocket-Protocol"); p != "" {
					t.Fatalf("subprotocol %q selected", p)
				}
			}
		})
	}
}

func TestWSHandshakeAllowedOrigins(t *testing.T) {
	h := &WSHandler{AllowedOrigins: []string{"https://app.example"}}
	for origin, want := range map[string]int{
		"https://app.example": 101,
		"HTTPS://APP.EXAMPLE": 101,
		"https://example.com": 403, // same origin is no longer implied
		"":                    101,
	} {
		s := &Server{Handler: upgradeHandler(h)}
		req := wsRequest("/")
		if origin != "" {
			req = wsRequest("/", "Origin: "+origin)
		}
		resps, _, _, _ := feed(t, s, s.getState(), req)
		if resps[0].StatusCode != want {
			t.Errorf("origin %q: %d, want %d", origin, resps[0].StatusCode, want)
		}
	}
}

// After the upgrade, process stops: what follows is frames, not requests.
func TestWSHandshakeStopsHTTP(t *testing.T) {
	s := &Server{Handler: func(c *Ctx) {
		if string(c.Path) == "/ws" {
			ws, _ := c.Upgrade(&WSHandler{})
			ws.SendText("welcome")
			c.Text(200, "ignored after Upgrade")
			return
		}
		c.Text(200, "plain")
	}}
	st := s.getState()
	first := "GET /plain HTTP/1.1\r\nHost: x\r\n\r\n" + wsRequest("/ws")
	input := first + string(clientFrame(true, opText, []byte("hi")))
	resps, _, consumed, closed := feed(t, s, st, input)
	if len(resps) != 2 || resps[0].StatusCode != 200 || resps[1].StatusCode != 101 {
		t.Fatalf("responses %v", resps)
	}
	if consumed != len(first) || closed {
		t.Fatalf("consumed %d, want %d; closed %v", consumed, len(first), closed)
	}
	frames := serverFrames(t, st.ctx.ws.out)
	if len(frames) != 1 || string(frames[0].payload) != "welcome" {
		t.Fatalf("frames %+v", frames)
	}
}

func TestWSHandshakeDuringShutdown(t *testing.T) {
	s := &Server{Handler: upgradeHandler(&WSHandler{})}
	s.wsShutdown.Store(true)
	resps, _, _, _ := feed(t, s, s.getState(), wsRequest("/"))
	if resps[0].StatusCode != 503 {
		t.Fatalf("status %d", resps[0].StatusCode)
	}
}

// Frames, through WSConn.process without gnet.

type wsHarness struct {
	t       testing.TB
	ws      *WSConn
	msgs    []string
	inbound []byte
	closed  bool
}

func newWSHarness(t testing.TB, h *WSHandler) *wsHarness {
	t.Helper()
	hs := &wsHarness{t: t}
	if h == nil {
		h = &WSHandler{}
	}
	h.OnMessage = func(_ *WSConn, typ WSMessageType, data []byte) {
		kind := "text"
		if typ == WSBinary {
			kind = "binary"
		}
		hs.msgs = append(hs.msgs, kind+":"+string(data))
	}
	s := &Server{Handler: upgradeHandler(h)}
	st := s.getState()
	if resps, _, _, _ := feed(t, s, st, wsRequest("/")); resps[0].StatusCode != 101 {
		t.Fatalf("handshake: %d", resps[0].StatusCode)
	}
	hs.ws = st.ctx.ws
	return hs
}

// send delivers b to the connection the way wsTraffic does, in chunks of
// the given size (0: all at once).
func (hs *wsHarness) send(b []byte, chunk int) {
	if chunk <= 0 {
		chunk = len(b)
	}
	for len(b) > 0 && !hs.closed {
		n := min(chunk, len(b))
		hs.inbound = append(hs.inbound, b[:n]...)
		b = b[n:]
		if len(hs.inbound) < hs.ws.need {
			continue
		}
		consumed, closeConn := hs.ws.serve(hs.inbound)
		hs.inbound = hs.inbound[consumed:]
		hs.closed = closeConn
	}
}

func (hs *wsHarness) output() []wsFrame {
	frames := serverFrames(hs.t, hs.ws.out)
	hs.ws.out = hs.ws.out[:0]
	return frames
}

func concat(frames ...[]byte) []byte {
	return bytes.Join(frames, nil)
}

func TestWSFrames(t *testing.T) {
	text := func(s string) []byte { return clientFrame(true, opText, []byte(s)) }
	big := strings.Repeat("x", 70000)

	for _, tc := range []struct {
		name   string
		input  []byte
		msgs   []string
		out    []string // frames sent back: "pong:payload" or "close:code:reason"
		closed bool
	}{
		{name: "text", input: text("hello"), msgs: []string{"text:hello"}},
		{name: "binary", input: clientFrame(true, opBinary, []byte{0, 1, 2}), msgs: []string{"binary:\x00\x01\x02"}},
		{name: "empty", input: text(""), msgs: []string{"text:"}},
		{name: "16-bit length", input: text(strings.Repeat("y", 300)), msgs: []string{"text:" + strings.Repeat("y", 300)}},
		{name: "64-bit length", input: text(big), msgs: []string{"text:" + big}},
		{name: "several", input: concat(text("a"), text("b"), text("c")), msgs: []string{"text:a", "text:b", "text:c"}},
		{
			name: "fragmented, ping in between",
			input: concat(
				clientFrame(false, opText, []byte("Hel")),
				clientFrame(true, opPing, []byte("p")),
				clientFrame(false, opContinuation, []byte("lo, ")),
				clientFrame(true, opContinuation, []byte("world")),
			),
			msgs: []string{"text:Hello, world"},
			out:  []string{"pong:p"},
		},
		{
			name: "code point split across fragments",
			input: concat(
				clientFrame(false, opText, []byte("\xce")),
				clientFrame(true, opContinuation, []byte("\xba")),
			),
			msgs: []string{"text:κ"},
		},
		{name: "ping", input: clientFrame(true, opPing, []byte("abc")), out: []string{"pong:abc"}},
		{name: "unsolicited pong", input: concat(clientFrame(true, opPong, []byte("x")), text("a")), msgs: []string{"text:a"}},

		{name: "close", input: concat(clientFrame(true, opClose, closePayload(1000, "bye")), text("after")), out: []string{"close:1000:"}, closed: true},
		{name: "close without code", input: clientFrame(true, opClose, nil), out: []string{"close:"}, closed: true},
		{name: "close 3000", input: clientFrame(true, opClose, closePayload(3000, "")), out: []string{"close:3000:"}, closed: true},
		{name: "close 4999", input: clientFrame(true, opClose, closePayload(4999, "")), out: []string{"close:4999:"}, closed: true},
		{name: "close one byte", input: clientFrame(true, opClose, []byte{3}), out: []string{"close:1002:"}, closed: true},
		{name: "close code 999", input: clientFrame(true, opClose, closePayload(999, "")), out: []string{"close:1002:"}, closed: true},
		{name: "close code 1004", input: clientFrame(true, opClose, closePayload(1004, "")), out: []string{"close:1002:"}, closed: true},
		{name: "close code 1005", input: clientFrame(true, opClose, closePayload(1005, "")), out: []string{"close:1002:"}, closed: true},
		{name: "close code 1006", input: clientFrame(true, opClose, closePayload(1006, "")), out: []string{"close:1002:"}, closed: true},
		{name: "close code 2999", input: clientFrame(true, opClose, closePayload(2999, "")), out: []string{"close:1002:"}, closed: true},
		{name: "close code 5000", input: clientFrame(true, opClose, closePayload(5000, "")), out: []string{"close:1002:"}, closed: true},
		{name: "close reason not UTF-8", input: clientFrame(true, opClose, closePayload(1000, "\xff")), out: []string{"close:1007:"}, closed: true},

		{name: "invalid UTF-8", input: text("a\xffb"), out: []string{"close:1007:invalid UTF-8"}, closed: true},
		{name: "surrogate", input: text("\xed\xa0\x80"), out: []string{"close:1007:invalid UTF-8"}, closed: true},
		{
			name: "invalid UTF-8 fails fast",
			input: concat(
				clientFrame(false, opText, []byte("ok\xff")),
				clientFrame(true, opContinuation, []byte("never")),
			),
			out: []string{"close:1007:invalid UTF-8"}, closed: true,
		},
		{
			name: "truncated code point at the end",
			input: concat(
				clientFrame(false, opText, []byte("ok")),
				clientFrame(true, opContinuation, []byte("\xe2\x82")),
			),
			out: []string{"close:1007:invalid UTF-8"}, closed: true,
		},
		// Strict: the rest of the frame is never sent, the error is found
		// in the part that arrived (when the input is chunked).
		{name: "invalid UTF-8 in an incomplete frame", input: clientFrame(true, opText, []byte("ok\xff"+strings.Repeat("x", 100)))[:20], out: []string{"close:1007:invalid UTF-8"}, closed: true},
		{name: "binary is not UTF-8 checked", input: clientFrame(true, opBinary, []byte{0xff}), msgs: []string{"binary:\xff"}},

		{name: "unmasked", input: rawFrame(0x81, []byte("x"), false), out: []string{"close:1002:frame not masked"}, closed: true},
		{name: "RSV1", input: rawFrame(0xC1, []byte("x"), true), out: []string{"close:1002:reserved bits set"}, closed: true},
		{name: "RSV3", input: rawFrame(0x91, []byte("x"), true), out: []string{"close:1002:reserved bits set"}, closed: true},
		{name: "opcode 3", input: clientFrame(true, 3, nil), out: []string{"close:1002:unknown opcode"}, closed: true},
		{name: "opcode 11", input: clientFrame(true, 11, nil), out: []string{"close:1002:unknown opcode"}, closed: true},
		{name: "lone continuation", input: clientFrame(true, opContinuation, []byte("x")), out: []string{"close:1002:unexpected continuation frame"}, closed: true},
		{
			name:  "new message inside a fragmented one",
			input: concat(clientFrame(false, opText, []byte("a")), text("b")),
			out:   []string{"close:1002:expected a continuation frame"}, closed: true,
		},
		{name: "fragmented ping", input: clientFrame(false, opPing, nil), out: []string{"close:1002:invalid control frame"}, closed: true},
		{name: "ping of 126 bytes", input: clientFrame(true, opPing, make([]byte, 126)), out: []string{"close:1002:invalid control frame"}, closed: true},
		{name: "too big", input: text(strings.Repeat("z", 1025)), out: []string{"close:1009:"}, closed: true},
		{
			name:  "too big in fragments",
			input: concat(clientFrame(false, opText, make([]byte, 600)), clientFrame(true, opContinuation, make([]byte, 600))),
			out:   []string{"close:1009:"}, closed: true,
		},
		// A 64-bit length of 2^63: refused from the header alone.
		{name: "huge length", input: []byte{0x82, 0xFF, 0x80, 0, 0, 0, 0, 0, 0, 0}, out: []string{"close:1009:"}, closed: true},
	} {
		for _, chunk := range []int{0, 1, 7} {
			t.Run(tc.name+"/chunk="+strconv.Itoa(chunk), func(t *testing.T) {
				if tc.name == "64-bit length" && chunk == 1 {
					t.Skip("slow")
				}
				maxMessage := 1024
				if tc.name == "64-bit length" {
					maxMessage = 1 << 20
				}
				hs := newWSHarness(t, &WSHandler{MaxMessageBytes: maxMessage})
				hs.send(tc.input, chunk)

				if strings.Join(hs.msgs, "|") != strings.Join(tc.msgs, "|") {
					t.Fatalf("messages %.60q, want %.60q", hs.msgs, tc.msgs)
				}
				var out []string
				for _, f := range hs.output() {
					switch f.op {
					case opPong:
						out = append(out, "pong:"+string(f.payload))
					case opClose:
						if len(f.payload) == 0 {
							out = append(out, "close:")
						} else {
							out = append(out, "close:"+strconv.Itoa(int(binary.BigEndian.Uint16(f.payload)))+":"+string(f.payload[2:]))
						}
					default:
						out = append(out, "op"+strconv.Itoa(int(f.op)))
					}
				}
				if strings.Join(out, "|") != strings.Join(tc.out, "|") {
					t.Fatalf("output %q, want %q", out, tc.out)
				}
				if hs.closed != tc.closed {
					t.Fatalf("closed %v, want %v", hs.closed, tc.closed)
				}
			})
		}
	}
}

func TestWSSendAndClose(t *testing.T) {
	hs := newWSHarness(t, nil)
	ws := hs.ws

	if err := ws.Send(WSText, []byte{0xff}); err != ErrWSInvalidMessage {
		t.Fatalf("invalid text: %v", err)
	}
	if err := ws.SendText("\xff"); err != ErrWSInvalidMessage {
		t.Fatalf("invalid text: %v", err)
	}
	if err := ws.Send(WSMessageType(opPing), nil); err != ErrWSInvalidMessage {
		t.Fatalf("ping as a message: %v", err)
	}
	for _, code := range []int{0, 999, 1004, 1005, 1006, 1015, 2999, 5000} {
		if err := ws.Close(code, ""); err != ErrWSInvalidClose {
			t.Fatalf("Close(%d): %v", code, err)
		}
	}
	if err := ws.Close(1000, strings.Repeat("r", 124)); err != ErrWSInvalidClose {
		t.Fatalf("long reason: %v", err)
	}

	if err := ws.Send(WSBinary, []byte{0xff}); err != nil {
		t.Fatal(err)
	}
	if err := ws.Close(4000, strings.Repeat("r", 123)); err != nil {
		t.Fatal(err)
	}
	if err := ws.SendText("late"); err != ErrWSClosed {
		t.Fatalf("Send after Close: %v", err)
	}
	if err := ws.Close(1000, ""); err != ErrWSClosed {
		t.Fatalf("second Close: %v", err)
	}

	// Messages received while closing are dropped; the peer's close ends it.
	hs.send(concat(
		clientFrame(true, opText, []byte("dropped")),
		clientFrame(true, opPing, nil),
		clientFrame(true, opClose, closePayload(4000, "")),
	), 0)
	if len(hs.msgs) != 0 || !hs.closed {
		t.Fatalf("messages %q, closed %v", hs.msgs, hs.closed)
	}
	frames := hs.output()
	if len(frames) != 2 || frames[0].op != opBinary || frames[1].op != opClose {
		t.Fatalf("frames %+v", frames)
	}
	if code := binary.BigEndian.Uint16(frames[1].payload); code != 4000 {
		t.Fatalf("close code %d", code)
	}
	if ws.peerCode != 4000 {
		t.Fatalf("peer code %d", ws.peerCode)
	}
}

func TestWSOutboundLimit(t *testing.T) {
	hs := newWSHarness(t, &WSHandler{MaxOutboundBytes: 1000})
	if err := hs.ws.Send(WSBinary, make([]byte, 900)); err != nil {
		t.Fatal(err)
	}
	if err := hs.ws.Send(WSBinary, make([]byte, 200)); err != ErrWSOutboundFull {
		t.Fatalf("got %v", err)
	}
	if err := hs.ws.Send(WSBinary, nil); err != ErrWSClosed {
		t.Fatalf("after overflow: %v", err)
	}
}

func TestWSRecoversPanic(t *testing.T) {
	defer log.SetOutput(log.Writer())
	log.SetOutput(io.Discard)

	hs := newWSHarness(t, nil)
	hs.ws.h.OnMessage = func(*WSConn, WSMessageType, []byte) { panic("boom") }
	hs.send(clientFrame(true, opText, []byte("x")), 0)
	frames := hs.output()
	if !hs.closed || len(frames) != 1 || binary.BigEndian.Uint16(frames[0].payload) != CloseInternalError {
		t.Fatalf("closed %v, frames %+v", hs.closed, frames)
	}
}

func TestWSProcessDoesNotAllocate(t *testing.T) {
	hs := newWSHarness(t, nil)
	hs.ws.h.OnMessage = func(ws *WSConn, typ WSMessageType, data []byte) {
		ws.Send(typ, data)
	}
	frame := clientFrame(true, opText, []byte("hello, world"))
	buf := make([]byte, len(frame))
	run := func() {
		copy(buf, frame) // process unmasks in place
		if consumed, closed := hs.ws.process(buf); consumed != len(buf) || closed {
			t.Fatal("frame not processed")
		}
		hs.ws.out = hs.ws.out[:0]
	}
	run()
	if n := testing.AllocsPerRun(1000, run); n != 0 {
		t.Fatalf("%v allocations per message", n)
	}
}

func BenchmarkWSProcess(b *testing.B) {
	hs := newWSHarness(b, nil)
	hs.ws.h.OnMessage = func(ws *WSConn, typ WSMessageType, data []byte) {
		ws.Send(typ, data)
	}
	frame := clientFrame(true, opText, []byte(strings.Repeat("x", 128)))
	buf := make([]byte, len(frame))
	b.SetBytes(int64(len(frame)))
	b.ReportAllocs()
	for b.Loop() {
		copy(buf, frame)
		hs.ws.process(buf)
		hs.ws.out = hs.ws.out[:0]
	}
}

func FuzzWSProcess(f *testing.F) {
	f.Add(clientFrame(true, opText, []byte("hello")))
	f.Add(concat(clientFrame(false, opText, []byte("a")), clientFrame(true, opPing, nil), clientFrame(true, opContinuation, []byte("b"))))
	f.Add(clientFrame(true, opClose, closePayload(1000, "x")))
	f.Add([]byte{0x82, 0xFF, 0x80, 0, 0, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, input []byte) {
		hs := newWSHarness(t, &WSHandler{MaxMessageBytes: 4096})
		hs.send(input, 0)
		if !hs.closed && len(hs.inbound) > len(input) {
			t.Fatal("consumed more than received")
		}
		hs.output() // whatever was sent back must be well formed
	})
}

// Through gnet and real sockets.

type wsTestClient struct {
	t    *testing.T
	conn net.Conn
	br   *bufio.Reader
	resp *http.Response
}

func dialWS(t *testing.T, addr, path string, lines ...string) *wsTestClient {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	c := &wsTestClient{t: t, conn: conn, br: bufio.NewReader(conn)}
	if _, err := io.WriteString(conn, wsRequest(path, lines...)); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	c.resp, err = http.ReadResponse(c.br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.resp.StatusCode != 101 {
		t.Fatalf("handshake: %s", c.resp.Status)
	}
	if got := c.resp.Header.Get("Sec-WebSocket-Accept"); got != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatalf("Sec-WebSocket-Accept: %q", got)
	}
	return c
}

func (c *wsTestClient) write(frames ...[]byte) {
	c.t.Helper()
	if _, err := c.conn.Write(concat(frames...)); err != nil {
		c.t.Fatal(err)
	}
}

func (c *wsTestClient) read() wsFrame {
	c.t.Helper()
	c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	f, err := readServerFrame(c.br)
	if err != nil {
		c.t.Fatalf("reading a frame: %v", err)
	}
	return f
}

func (c *wsTestClient) expectMessage(op byte, payload string) {
	c.t.Helper()
	f := c.read()
	if !f.fin || f.op != op || string(f.payload) != payload {
		c.t.Fatalf("got fin=%v op=%d %.40q, want op=%d %.40q", f.fin, f.op, f.payload, op, payload)
	}
}

// expectClose reads the close frame, skipping pings.
func (c *wsTestClient) expectClose(code int, reason string) {
	c.t.Helper()
	for {
		f := c.read()
		if f.op == opPing {
			continue
		}
		if f.op != opClose || len(f.payload) < 2 {
			c.t.Fatalf("got op=%d %q, want close %d", f.op, f.payload, code)
		}
		if got := int(binary.BigEndian.Uint16(f.payload)); got != code || string(f.payload[2:]) != reason {
			c.t.Fatalf("got close %d %q, want %d %q", got, f.payload[2:], code, reason)
		}
		return
	}
}

// expectEOF waits for the server to close the TCP connection.
func (c *wsTestClient) expectEOF(within time.Duration) {
	c.t.Helper()
	c.conn.SetReadDeadline(time.Now().Add(within))
	if _, err := io.Copy(io.Discard, c.br); err != nil {
		c.t.Fatalf("connection not closed within %v: %v", within, err)
	}
}

type closeEvent struct {
	code   int
	reason string
}

func closeRecorder() (func(*WSConn, int, string), chan closeEvent) {
	ch := make(chan closeEvent, 16)
	return func(_ *WSConn, code int, reason string) { ch <- closeEvent{code, reason} }, ch
}

func waitCloseEvent(t *testing.T, ch chan closeEvent, code int) {
	t.Helper()
	select {
	case ev := <-ch:
		if ev.code != code {
			t.Fatalf("OnClose code %d %q, want %d", ev.code, ev.reason, code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("OnClose not called")
	}
}

func echoHandler() *WSHandler {
	return &WSHandler{
		OnMessage: func(ws *WSConn, typ WSMessageType, data []byte) {
			ws.Send(typ, data)
		},
	}
}

func startWSServer(t *testing.T, h *WSHandler) string {
	t.Helper()
	r := NewRouter()
	r.GET("/", func(c *Ctx) { c.Text(200, "Hello, World!") })
	r.GET("/ws", func(c *Ctx) {
		if ws, err := c.Upgrade(h); err == nil && c.Query != nil {
			ws.SendText("welcome " + string(c.Query))
		}
	})
	return startServerWith(t, &Server{Handler: r.Serve})
}

func TestWSServerEcho(t *testing.T) {
	onClose, closes := closeRecorder()
	h := echoHandler()
	h.OnClose = onClose
	addr := startWSServer(t, h)
	c := dialWS(t, addr, "/ws?alice")
	c.expectMessage(opText, "welcome alice")

	big := strings.Repeat("0123456789", 100_000) // 64-bit length
	c.write(clientFrame(true, opText, []byte("ciao")))
	c.expectMessage(opText, "ciao")
	c.write(clientFrame(true, opBinary, []byte(big)))
	c.expectMessage(opBinary, big)

	// Many messages in one write, and one message split over many writes.
	var many [][]byte
	for i := range 100 {
		many = append(many, clientFrame(true, opText, []byte(strconv.Itoa(i))))
	}
	c.write(many...)
	for i := range 100 {
		c.expectMessage(opText, strconv.Itoa(i))
	}
	frame := clientFrame(true, opText, []byte(strings.Repeat("s", 1000)))
	for len(frame) > 0 {
		n := min(97, len(frame))
		c.write(frame[:n])
		frame = frame[n:]
		time.Sleep(time.Millisecond)
	}
	c.expectMessage(opText, strings.Repeat("s", 1000))

	c.write(clientFrame(true, opPing, []byte("are you there")))
	c.expectMessage(opPong, "are you there")

	// Closing handshake started by the client: echo, then the server closes
	// the TCP connection first.
	c.write(clientFrame(true, opClose, closePayload(1000, "done")))
	c.expectClose(1000, "")
	c.expectEOF(5 * time.Second)
	waitCloseEvent(t, closes, 1000)
}

// HTTP requests and the upgrade on the same connection, and the first frame
// in the same packet as the handshake.
func TestWSServerSameConnection(t *testing.T) {
	addr := startWSServer(t, echoHandler())
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	br := bufio.NewReader(conn)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	io.WriteString(conn, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("%v %v", resp, err)
	}
	io.Copy(io.Discard, resp.Body)

	conn.Write(concat([]byte(wsRequest("/ws")), clientFrame(true, opText, []byte("early"))))
	if resp, err = http.ReadResponse(br, nil); err != nil || resp.StatusCode != 101 {
		t.Fatalf("%v %v", resp, err)
	}
	c := &wsTestClient{t: t, conn: conn, br: br}
	c.expectMessage(opText, "early")
}

func TestWSServerClose(t *testing.T) {
	onClose, closes := closeRecorder()
	h := &WSHandler{
		CloseTimeout: 300 * time.Millisecond,
		OnMessage: func(ws *WSConn, _ WSMessageType, data []byte) {
			ws.SendText("last")
			ws.Close(4000, string(data))
		},
		OnClose: onClose,
	}
	addr := startWSServer(t, h)

	// A client that answers the close frame.
	c := dialWS(t, addr, "/ws")
	c.write(clientFrame(true, opText, []byte("bye")))
	c.expectMessage(opText, "last")
	c.expectClose(4000, "bye")
	c.write(clientFrame(true, opClose, closePayload(4000, "")))
	c.expectEOF(time.Second)
	waitCloseEvent(t, closes, 4000)

	// One that does not: dropped after CloseTimeout.
	c = dialWS(t, addr, "/ws")
	c.write(clientFrame(true, opText, []byte("bye")))
	c.expectMessage(opText, "last")
	c.expectClose(4000, "bye")
	begin := time.Now()
	c.expectEOF(3 * time.Second)
	if d := time.Since(begin); d < 200*time.Millisecond {
		t.Fatalf("closed after %v, before CloseTimeout", d)
	}
	waitCloseEvent(t, closes, CloseAbnormal)
}

func TestWSServerProtocolError(t *testing.T) {
	onClose, closes := closeRecorder()
	h := echoHandler()
	h.OnClose = onClose
	c := dialWS(t, startWSServer(t, h), "/ws")
	c.write(rawFrame(0x81, []byte("unmasked"), false))
	c.expectClose(CloseProtocolError, "frame not masked")
	c.expectEOF(time.Second)
	waitCloseEvent(t, closes, CloseAbnormal)
}

func TestWSServerIdle(t *testing.T) {
	onClose, closes := closeRecorder()
	h := echoHandler()
	h.IdleTimeout = 300 * time.Millisecond
	h.OnClose = onClose
	addr := startWSServer(t, h)

	// Answers the pings: stays connected well past IdleTimeout.
	alive := dialWS(t, addr, "/ws")
	go func() {
		for {
			f, err := readServerFrame(alive.br)
			if err != nil {
				return
			}
			if f.op == opPing {
				alive.conn.Write(clientFrame(true, opPong, f.payload))
			}
		}
	}()

	// Silent: pinged, then dropped.
	silent := dialWS(t, addr, "/ws")
	f := silent.read()
	if f.op != opPing {
		t.Fatalf("op %d, want a ping", f.op)
	}
	silent.expectEOF(2 * time.Second)
	waitCloseEvent(t, closes, CloseAbnormal)

	time.Sleep(time.Second)
	select {
	case ev := <-closes:
		t.Fatalf("the client answering pings was dropped: %+v", ev)
	default:
	}
}

// Send from goroutines other than the event loop, and to connections on
// other event loops.
func TestWSServerSendFromGoroutines(t *testing.T) {
	var (
		mu    sync.Mutex
		conns []*WSConn
	)
	h := &WSHandler{
		OnMessage: func(_ *WSConn, _ WSMessageType, data []byte) {
			mu.Lock()
			defer mu.Unlock()
			for _, ws := range conns {
				ws.Send(WSText, data)
			}
		},
	}
	r := NewRouter()
	r.GET("/ws", func(c *Ctx) {
		ws, err := c.Upgrade(h)
		if err != nil {
			return
		}
		mu.Lock()
		conns = append(conns, ws)
		mu.Unlock()
		if c.Query != nil {
			go func() {
				for i := range 1000 {
					if err := ws.SendText(strconv.Itoa(i)); err != nil {
						panic(err)
					}
				}
			}()
		}
	})
	addr := startServerWith(t, &Server{Handler: r.Serve})

	clients := []*wsTestClient{dialWS(t, addr, "/ws"), dialWS(t, addr, "/ws"), dialWS(t, addr, "/ws")}
	clients[0].write(clientFrame(true, opText, []byte("to everyone")))
	for _, c := range clients {
		c.expectMessage(opText, "to everyone")
	}

	c := dialWS(t, addr, "/ws?count")
	for i := range 1000 {
		c.expectMessage(opText, strconv.Itoa(i))
	}
}

func TestWSServerOutboundLimit(t *testing.T) {
	onClose, closes := closeRecorder()
	result := make(chan error, 1)
	h := &WSHandler{MaxOutboundBytes: 256 << 10, OnClose: onClose}
	r := NewRouter()
	r.GET("/ws", func(c *Ctx) {
		ws, _ := c.Upgrade(h)
		go func() {
			chunk := make([]byte, 32<<10)
			for range 100_000 {
				if err := ws.Send(WSBinary, chunk); err != nil {
					result <- err
					return
				}
			}
			result <- nil
		}()
	})
	addr := startServerWith(t, &Server{Handler: r.Serve})
	c := dialWS(t, addr, "/ws") // never reads

	select {
	case err := <-result:
		if err != ErrWSOutboundFull && err != ErrWSClosed {
			t.Fatalf("Send: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the outbound limit was never reached")
	}
	waitCloseEvent(t, closes, CloseAbnormal)
	c.expectEOF(5 * time.Second)
}

func TestWSServerShutdown(t *testing.T) {
	onClose, closes := closeRecorder()
	h := echoHandler()
	h.OnClose = onClose
	r := NewRouter()
	r.GET("/ws", func(c *Ctx) { c.Upgrade(h) })
	s := &Server{Handler: r.Serve}
	addr, done := runServer(t, s)

	clients := []*wsTestClient{dialWS(t, addr, "/ws"), dialWS(t, addr, "/ws")}
	for _, c := range clients {
		c.write(clientFrame(true, opText, []byte("hi")))
		c.expectMessage(opText, "hi")
	}

	shutdown := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		shutdown <- s.Shutdown(ctx)
	}()

	for _, c := range clients {
		c.expectClose(CloseGoingAway, "server shutting down")
		c.write(clientFrame(true, opClose, closePayload(CloseGoingAway, "")))
		c.expectEOF(time.Second)
	}
	waitCloseEvent(t, closes, CloseGoingAway)
	waitCloseEvent(t, closes, CloseGoingAway)

	select {
	case err := <-shutdown:
		if err != nil {
			t.Fatalf("Shutdown: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Shutdown did not return once the clients answered")
	}
	if err := <-done; err != nil {
		t.Fatalf("ListenAndServe: %v", err)
	}
}
