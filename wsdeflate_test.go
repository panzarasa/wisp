package wisp

import (
	"bytes"
	"compress/flate"
	"io"
	"strings"
	"testing"
	"unicode/utf8"
)

// wsConnect upgrades a connection to h with the extra handshake lines and
// returns it with the handshake response.
func wsConnect(t *testing.T, h *WSHandler, lines ...string) (*WSConn, string) {
	t.Helper()
	s := &Server{Handler: upgradeHandler(h)}
	st := s.getState()
	resps, _, _, _ := feed(t, s, st, wsRequest("/", lines...))
	if len(resps) != 1 || resps[0].StatusCode != 101 {
		t.Fatalf("handshake: %v", resps)
	}
	ws := st.ctx.ws
	ws.out = ws.out[:0] // the 101 response
	return ws, resps[0].Header.Get("Sec-WebSocket-Extensions")
}

// feedWS passes b to ws as wsTraffic does and returns the frames sent back
// and whether the connection is closing.
func feedWS(t *testing.T, ws *WSConn, b []byte) ([]wsFrame, bool) {
	t.Helper()
	consumed, closed := ws.serve(b)
	if !closed && consumed != len(b) {
		t.Fatalf("consumed %d of %d", consumed, len(b))
	}
	frames := serverFrames(t, ws.out)
	ws.out = ws.out[:0]
	return frames, closed
}

func TestDeflateNegotiation(t *testing.T) {
	const both = "permessage-deflate; server_no_context_takeover; client_no_context_takeover"
	for _, tc := range []struct {
		offer    string
		takeover bool
		want     string
	}{
		{"permessage-deflate", false, both},
		{"PerMessage-Deflate ; client_max_window_bits", false, both},
		{"permessage-deflate; client_max_window_bits=\"12\"", false, both},
		{"permessage-deflate; server_max_window_bits=10", false, both + "; server_max_window_bits=10"},
		{"permessage-deflate; server_max_window_bits=15", false, both + "; server_max_window_bits=15"},
		{"permessage-deflate; server_max_window_bits", false, ""},
		{"permessage-deflate; server_max_window_bits=7", false, ""},
		{"permessage-deflate; client_max_window_bits=16", false, ""},
		{"permessage-deflate; server_no_context_takeover=1", false, ""},
		{"permessage-deflate; server_no_context_takeover; server_no_context_takeover", false, ""},
		{"permessage-deflate; foo", false, ""},
		{"permessage-deflate; server_max_window_bits=9, permessage-deflate", false, both + "; server_max_window_bits=9"},
		{"permessage-deflate; foo, permessage-deflate", false, both},
		{"x-webkit-deflate-frame, permessage-deflate; client_max_window_bits", false, both},
		{"x-webkit-deflate-frame", false, ""},
		{"permessage-deflate", true, "permessage-deflate"},
		{"permessage-deflate; client_no_context_takeover", true, "permessage-deflate; client_no_context_takeover"},
		{"permessage-deflate; server_no_context_takeover", true, "permessage-deflate; server_no_context_takeover"},
	} {
		h := &WSHandler{Compression: &WSCompression{ContextTakeover: tc.takeover}}
		ws, ext := wsConnect(t, h, "Sec-WebSocket-Extensions: "+tc.offer)
		if ext != tc.want || (ws.pmd != nil) != (tc.want != "") {
			t.Errorf("%q: got %q, want %q", tc.offer, ext, tc.want)
		}
	}

	// Not enabled, or OnFrame set: no compression.
	for _, h := range []*WSHandler{{}, {Compression: &WSCompression{}, OnFrame: func(*WSConn, WSMessageType, []byte, bool) {}}} {
		if ws, ext := wsConnect(t, h, "Sec-WebSocket-Extensions: permessage-deflate"); ext != "" || ws.pmd != nil {
			t.Errorf("negotiated %q", ext)
		}
	}
}

// clientDeflater compresses messages as a client does.
type clientDeflater struct {
	buf bytes.Buffer
	w   *flate.Writer
}

func newClientDeflater() *clientDeflater {
	d := &clientDeflater{}
	d.w, _ = flate.NewWriter(&d.buf, flate.BestCompression)
	return d
}

// compress returns a message compressed; the context carries over to the
// next message unless reset.
func (d *clientDeflater) compress(p []byte, reset bool) []byte {
	d.buf.Reset()
	d.w.Write(p)
	d.w.Flush()
	out := bytes.Clone(d.buf.Bytes()[:d.buf.Len()-4])
	if reset {
		d.w.Reset(&d.buf)
	}
	return out
}

func inflateMessage(t *testing.T, p []byte) string {
	t.Helper()
	b, err := io.ReadAll(flate.NewReader(io.MultiReader(bytes.NewReader(p), bytes.NewReader(deflateTail))))
	if err != nil {
		t.Fatalf("server sent invalid DEFLATE data: %v", err)
	}
	return string(b)
}

func TestDeflateMessages(t *testing.T) {
	var got []string
	h := &WSHandler{
		Compression:     &WSCompression{MinSize: 10},
		MaxMessageBytes: 1 << 16,
		OnMessage: func(ws *WSConn, typ WSMessageType, data []byte) {
			got = append(got, string(data))
			ws.Send(typ, data)
		},
	}
	ws, _ := wsConnect(t, h, "Sec-WebSocket-Extensions: permessage-deflate")
	cd := newClientDeflater()
	msg := strings.Repeat("hello, compression! ", 50)

	// A compressed message, echoed compressed.
	frames, closed := feedWS(t, ws, rawFrame(0xC1, cd.compress([]byte(msg), true), true))
	if closed || len(got) != 1 || got[0] != msg || len(frames) != 1 || !frames[0].rsv1 || !frames[0].fin || frames[0].op != opText {
		t.Fatalf("got %q, frames %+v, closed %v", got, frames, closed)
	}
	if len(frames[0].payload) >= len(msg)/4 {
		t.Errorf("%d bytes compressed to %d", len(msg), len(frames[0].payload))
	}
	if back := inflateMessage(t, frames[0].payload); back != msg {
		t.Fatalf("echo inflates to %q", back)
	}

	// Short and uncompressed: echoed uncompressed.
	frames, _ = feedWS(t, ws, clientFrame(true, opText, []byte("short")))
	if len(frames) != 1 || frames[0].rsv1 || string(frames[0].payload) != "short" {
		t.Fatalf("short: %+v", frames)
	}

	// Fragmented: RSV1 on the first frame only, a ping in between.
	c := cd.compress([]byte(msg), true)
	got = nil
	frames, closed = feedWS(t, ws, concat(
		rawFrame(0x42, c[:5], true),
		clientFrame(true, opPing, []byte("p")),
		rawFrame(0x00, c[5:20], true),
		rawFrame(0x80, c[20:], true),
	))
	if closed || len(got) != 1 || got[0] != msg || len(frames) != 2 || frames[0].op != opPong || inflateMessage(t, frames[1].payload) != msg {
		t.Fatalf("fragmented: got %q, frames %+v", got, frames)
	}

	// An empty compressed message.
	got = nil
	feedWS(t, ws, rawFrame(0xC2, []byte{0x00}, true))
	if len(got) != 1 || got[0] != "" {
		t.Fatalf("empty: %q", got)
	}

	for _, tc := range []struct {
		name  string
		frame []byte
		code  int
	}{
		{"RSV1 on a continuation", concat(rawFrame(0x41, c[:5], true), rawFrame(0xC0, c[5:], true)), CloseProtocolError},
		{"RSV1 on a ping", rawFrame(0xC9, nil, true), CloseProtocolError},
		{"invalid DEFLATE", rawFrame(0xC1, []byte{0xff, 0xff, 0xff}, true), CloseInvalidPayload},
		{"invalid UTF-8", rawFrame(0xC1, cd.compress([]byte("abc\xffdef"), true), true), CloseInvalidPayload},
		{"bomb", rawFrame(0xC2, cd.compress(make([]byte, 1<<20), true), true), CloseMessageTooBig},
	} {
		ws, _ := wsConnect(t, h, "Sec-WebSocket-Extensions: permessage-deflate")
		frames, closed := feedWS(t, ws, tc.frame)
		if !closed || len(frames) == 0 || frames[len(frames)-1].op != opClose {
			t.Errorf("%s: frames %+v, closed %v", tc.name, frames, closed)
			continue
		}
		if code, _, _ := parseClosePayload(frames[len(frames)-1].payload); code != tc.code {
			t.Errorf("%s: closed with %d, want %d", tc.name, code, tc.code)
		}
	}
}

func TestDeflateContextTakeover(t *testing.T) {
	var got []string
	h := &WSHandler{
		Compression: &WSCompression{ContextTakeover: true, MinSize: -1},
		OnMessage: func(ws *WSConn, typ WSMessageType, data []byte) {
			got = append(got, string(data))
			ws.Send(typ, data)
		},
	}
	ws, ext := wsConnect(t, h, "Sec-WebSocket-Extensions: permessage-deflate")
	if ext != "permessage-deflate" {
		t.Fatalf("negotiated %q", ext)
	}

	// The client keeps its context: the later messages refer to the earlier
	// ones, beyond the 32 KiB window too.
	cd := newClientDeflater()
	big := make([]byte, 40<<10)
	for i := range big {
		big[i] = byte('a' + i*7%26)
	}
	msgs := []string{strings.Repeat("abcdefgh", 100), strings.Repeat("abcdefgh", 100), string(big), string(big[:5000]) + "tail"}
	var echoed bytes.Buffer
	r := flate.NewReader(&echoed)
	for i, m := range msgs {
		c := cd.compress([]byte(m), false)
		if i == 1 && len(c) > 20 {
			t.Errorf("the repeated message compresses to %d bytes: context not kept", len(c))
		}
		frames, closed := feedWS(t, ws, rawFrame(0xC1, c, true))
		if closed || len(got) != i+1 || got[i] != m || len(frames) != 1 || !frames[0].rsv1 {
			t.Fatalf("message %d: closed %v, frames %d", i, closed, len(frames))
		}
		// The server keeps its context too: decompress with one reader.
		echoed.Write(frames[0].payload)
		echoed.Write([]byte{0, 0, 0xff, 0xff})
		back := make([]byte, len(m))
		if _, err := io.ReadFull(r, back); err != nil || string(back) != m {
			t.Fatalf("echo %d: %v", i, err)
		}
	}
	ws.pmd.release()
}

func TestDeflateHuffmanOnly(t *testing.T) {
	h := &WSHandler{
		Compression: &WSCompression{Level: flate.BestCompression},
		OnMessage:   func(ws *WSConn, typ WSMessageType, data []byte) { ws.Send(typ, data) },
	}
	ws, ext := wsConnect(t, h, "Sec-WebSocket-Extensions: permessage-deflate; server_max_window_bits=8")
	if !strings.HasSuffix(ext, "server_max_window_bits=8") || ws.pmd.level != flate.HuffmanOnly {
		t.Fatalf("negotiated %q, level %d", ext, ws.pmd.level)
	}
	msg := strings.Repeat("window ", 100)
	frames, _ := feedWS(t, ws, clientFrame(true, opText, []byte(msg)))
	if len(frames) != 1 || !frames[0].rsv1 || inflateMessage(t, frames[0].payload) != msg {
		t.Fatalf("frames %+v", frames)
	}
}

func TestWSNextWriter(t *testing.T) {
	ws, _ := wsConnect(t, &WSHandler{})

	w, err := ws.NextWriter(WSText)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ws.NextWriter(WSBinary); err != ErrWSBusy {
		t.Fatalf("second writer: %v", err)
	}
	euro := "€"
	w.Write([]byte("price: " + euro[:1]))
	ws.SendText("held back")
	ws.Close(CloseNormal, "") // control frames go through, held messages are dropped
	// After the close frame, no data frame.
	if _, err := w.Write([]byte(euro[1:])); err != ErrWSClosed {
		t.Fatalf("Write after the close frame: %v", err)
	}
	frames := serverFrames(t, ws.out)
	if len(frames) != 2 || frames[0].fin || frames[0].op != opText || frames[1].op != opClose {
		t.Fatalf("frames %+v", frames)
	}
	if err := w.Close(); err != ErrWSClosed {
		t.Fatalf("Close after the close frame: %v", err)
	}

	ws, _ = wsConnect(t, &WSHandler{})
	w, _ = ws.NextWriter(WSBinary)
	w.Write([]byte("a"))
	ws.Send(WSBinary, []byte("other"))
	w.Write([]byte("b"))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	frames = serverFrames(t, ws.out)
	var desc []string
	for _, f := range frames {
		desc = append(desc, string(rune('0'+f.op))+map[bool]string{true: "F", false: "-"}[f.fin]+string(f.payload))
	}
	if strings.Join(desc, " ") != "2-a 0-b 0F 2Fother" {
		t.Fatalf("frames %q", desc)
	}

	// Empty message.
	ws.out = ws.out[:0]
	w, _ = ws.NextWriter(WSText)
	w.Close()
	if frames := serverFrames(t, ws.out); len(frames) != 1 || !frames[0].fin || frames[0].op != opText || len(frames[0].payload) != 0 {
		t.Fatalf("empty: %+v", frames)
	}

	// Invalid UTF-8 closes the connection with 1011.
	ws.out = ws.out[:0]
	w, _ = ws.NextWriter(WSText)
	w.Write([]byte("ok"))
	if _, err := w.Write([]byte{0xff}); err != ErrWSInvalidMessage {
		t.Fatalf("invalid write: %v", err)
	}
	frames = serverFrames(t, ws.out)
	if len(frames) != 2 || frames[1].op != opClose {
		t.Fatalf("frames %+v", frames)
	}
	if code, _, _ := parseClosePayload(frames[1].payload); code != CloseInternalError {
		t.Fatalf("closed with %d", code)
	}

	// A message cut in the middle of a code point.
	ws, _ = wsConnect(t, &WSHandler{})
	w, _ = ws.NextWriter(WSText)
	w.Write([]byte(euro[:2]))
	if err := w.Close(); err != ErrWSInvalidMessage {
		t.Fatalf("truncated text: %v", err)
	}
}

func TestWSOnFrame(t *testing.T) {
	var got []string
	h := &WSHandler{
		MaxMessageBytes: 10,
		OnFrame: func(ws *WSConn, typ WSMessageType, data []byte, fin bool) {
			got = append(got, string(rune('0'+typ))+map[bool]string{true: "F", false: "-"}[fin]+string(data))
		},
		OnMessage: func(*WSConn, WSMessageType, []byte) { t.Error("OnMessage called") },
	}
	ws, _ := wsConnect(t, h)
	euro := "€"

	// A message larger than MaxMessageBytes, in frames that are not; a
	// code point split between two of them; a ping in between.
	frames, closed := feedWS(t, ws, concat(
		clientFrame(false, opText, []byte("12345678"+euro[:1])),
		clientFrame(true, opPing, nil),
		clientFrame(false, opContinuation, []byte(euro[1:]+"abcdefgh")),
		clientFrame(true, opContinuation, []byte("end")),
		clientFrame(true, opBinary, []byte{1}),
	))
	want := "1-12345678" + euro[:1] + " 1-" + euro[1:] + "abcdefgh 1Fend 2F\x01"
	if closed || strings.Join(got, " ") != want || len(frames) != 1 || frames[0].op != opPong {
		t.Fatalf("got %q, want %q; frames %+v", got, want, frames)
	}
	if !utf8.ValidString(strings.Join([]string{got[0][2:], got[1][2:], got[2][2:]}, "")) {
		t.Fatal("reassembled text is not UTF-8")
	}

	for _, tc := range []struct {
		name  string
		input []byte
		code  int
	}{
		{"frame too large", clientFrame(true, opBinary, make([]byte, 11)), CloseMessageTooBig},
		{"invalid UTF-8", clientFrame(true, opText, []byte{'a', 0xff}), CloseInvalidPayload},
		{"truncated code point", clientFrame(true, opText, []byte(euro[:2])), CloseInvalidPayload},
		{"truncated across frames", concat(clientFrame(false, opText, []byte(euro[:2])), clientFrame(true, opContinuation, nil)), CloseInvalidPayload},
	} {
		got = nil
		ws, _ := wsConnect(t, h)
		frames, closed := feedWS(t, ws, tc.input)
		if !closed || len(frames) == 0 || frames[len(frames)-1].op != opClose {
			t.Errorf("%s: frames %+v", tc.name, frames)
			continue
		}
		if code, _, _ := parseClosePayload(frames[len(frames)-1].payload); code != tc.code {
			t.Errorf("%s: closed with %d, want %d", tc.name, code, tc.code)
		}
	}
}
