package wisp

// permessage-deflate (RFC 7692): messages compressed with DEFLATE, marked by
// the RSV1 bit of their first frame.
//
// Without context takeover, the default, every message is compressed and
// decompressed on its own, so the flate writers and readers come from pools
// and a connection holds no compression state between messages. With it,
// each message may refer back to the previous ones: better ratios for
// repetitive traffic, but each connection keeps a flate writer (hundreds of
// KiB) and the last 32 KiB it received.

import (
	"compress/flate"
	"io"
	"slices"
	"strconv"
	"sync"
)

// WSCompression enables permessage-deflate on a WSHandler.
type WSCompression struct {
	// Level is the compress/flate level of the messages sent, from
	// flate.HuffmanOnly to flate.BestCompression (flate.BestSpeed if zero).
	Level int
	// MinSize: messages shorter than this are sent uncompressed
	// (DefaultWSCompressMinSize if zero; negative compresses every message).
	MinSize int
	// ContextTakeover keeps the compression context between messages, in
	// both directions, unless the client refuses it.
	ContextTakeover bool
}

const (
	DefaultWSCompressMinSize = 128

	deflateWindow = 32 << 10
)

// The end of a message compressed with a sync flush, which the sender strips
// (section 7.2.1), followed by an empty final block so that the reader ends
// with io.EOF.
var deflateTail = []byte("\x00\x00\xff\xff\x01\x00\x00\xff\xff")

// wsDeflate is the permessage-deflate state of a connection.
type wsDeflate struct {
	level   int
	minSize int
	// Context takeover: whether the client (clientNoCtx) and the server
	// (serverNoCtx) start every message afresh.
	serverNoCtx bool
	clientNoCtx bool

	// Receiving, on the loop.
	dict     []byte // the last 32 KiB received, with client context takeover
	inflated []byte

	// Sending, with server context takeover: the connection's own writer.
	sendMu sync.Mutex
	w      *deflater
}

// negotiateDeflate picks the first permessage-deflate offer of the client's
// Sec-WebSocket-Extensions headers that the server can accept (section 5),
// and returns the response's header value, or "" if none.
func negotiateDeflate(c *Ctx, cfg *WSCompression) (*wsDeflate, string) {
	for i := range c.req.Headers {
		h := &c.req.Headers[i]
		if !equalFold(h.Name, "Sec-WebSocket-Extensions") {
			continue
		}
		list := h.Value
		for len(list) > 0 {
			offer := list
			if j := indexByte(list, ','); j >= 0 {
				offer, list = list[:j], list[j+1:]
			} else {
				list = nil
			}
			if d, resp := acceptDeflate(offer, cfg); d != nil {
				return d, resp
			}
		}
	}
	return nil, ""
}

// acceptDeflate accepts one offer, "permessage-deflate; param; param=value",
// or returns nil.
func acceptDeflate(offer []byte, cfg *WSCompression) (*wsDeflate, string) {
	name, params := offer, []byte(nil)
	if j := indexByte(offer, ';'); j >= 0 {
		name, params = offer[:j], offer[j+1:]
	}
	if !equalFold(trimOWS(name), "permessage-deflate") {
		return nil, ""
	}

	level := cfg.Level
	if level < flate.HuffmanOnly || level > flate.BestCompression || level == flate.NoCompression {
		level = flate.BestSpeed
	}
	d := &wsDeflate{
		level:       level,
		minSize:     cfg.MinSize,
		serverNoCtx: !cfg.ContextTakeover,
		clientNoCtx: !cfg.ContextTakeover,
	}
	if d.minSize == 0 {
		d.minSize = DefaultWSCompressMinSize
	}
	serverBits := 0
	var seen [4]bool
	for len(params) > 0 {
		p := params
		if j := indexByte(params, ';'); j >= 0 {
			p, params = params[:j], params[j+1:]
		} else {
			params = nil
		}
		key, value, hasValue := p, []byte(nil), false
		if j := indexByte(p, '='); j >= 0 {
			key, value, hasValue = p[:j], trimOWS(p[j+1:]), true
			if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
				value = value[1 : len(value)-1]
			}
		}
		var k int
		switch string(trimOWS(key)) {
		case "server_no_context_takeover":
			k = 0
			if hasValue {
				return nil, ""
			}
			d.serverNoCtx = true
		case "client_no_context_takeover":
			k = 1
			if hasValue {
				return nil, ""
			}
			d.clientNoCtx = true
		case "server_max_window_bits":
			k = 2
			if serverBits = windowBits(value); serverBits == 0 {
				return nil, ""
			}
		case "client_max_window_bits":
			// The client can take a smaller window; the server never asks
			// for one, so it is not echoed.
			k = 3
			if hasValue && windowBits(value) == 0 {
				return nil, ""
			}
		default:
			return nil, ""
		}
		if seen[k] {
			return nil, ""
		}
		seen[k] = true
	}

	resp := "permessage-deflate"
	if d.serverNoCtx {
		resp += "; server_no_context_takeover"
	}
	if d.clientNoCtx {
		resp += "; client_no_context_takeover"
	}
	if serverBits != 0 {
		// compress/flate always uses a 32 KiB window. Huffman-only output
		// refers back to nothing, so it fits any window the client asks for.
		if serverBits < 15 {
			d.level = flate.HuffmanOnly
		}
		resp += "; server_max_window_bits=" + strconv.Itoa(serverBits)
	}
	return d, resp
}

// windowBits parses a window size of 8 to 15 bits, or returns 0.
func windowBits(v []byte) int {
	switch {
	case len(v) == 1 && v[0] == '8':
		return 8
	case len(v) == 1 && v[0] == '9':
		return 9
	case len(v) == 2 && v[0] == '1' && v[1] >= '0' && v[1] <= '5':
		return 10 + int(v[1]-'0')
	}
	return 0
}

// deflater is a flate writer that compresses into a buffer of its own.
type deflater struct {
	fw  *flate.Writer
	buf []byte
}

func (d *deflater) Write(p []byte) (int, error) {
	d.buf = append(d.buf, p...)
	return len(p), nil
}

// deflaterPools hold writers by level, from flate.HuffmanOnly (-2).
var deflaterPools [flate.BestCompression + 3]sync.Pool

func getDeflater(level int) *deflater {
	if d, ok := deflaterPools[level+2].Get().(*deflater); ok {
		return d
	}
	d := &deflater{}
	d.fw, _ = flate.NewWriter(d, level) // level is valid: acceptDeflate checked it
	return d
}

func putDeflater(level int, d *deflater) {
	d.fw.Reset(d)
	d.buf = d.buf[:0]
	if cap(d.buf) > maxPooledBuffer {
		d.buf = nil
	}
	deflaterPools[level+2].Put(d)
}

// compress returns p compressed as a message, valid until the next use of
// d.
func (d *deflater) compress(p []byte) []byte {
	d.buf = d.buf[:0]
	_, _ = d.fw.Write(p)
	_ = d.fw.Flush()
	// The sync flush ends with an empty stored block, 00 00 ff ff, which is
	// not sent (section 7.2.1).
	return d.buf[:len(d.buf)-4]
}

// sendCompressed queues data as a compressed message if it should be; it
// returns false if data goes uncompressed.
func (ws *WSConn) sendCompressed(op byte, data []byte) (bool, error) {
	d := ws.pmd
	if d == nil || len(data) < d.minSize {
		return false, nil
	}
	ws.mu.Lock()
	gone := ws.closing || ws.closed
	ws.mu.Unlock()
	if gone {
		return true, ErrWSClosed // not worth compressing
	}
	b0 := 0x80 | 0x40 | op
	if d.serverNoCtx {
		w := getDeflater(d.level)
		err := wsQueue(ws, b0, w.compress(data))
		putDeflater(d.level, w)
		return true, err
	}
	// The messages must reach the wire in the order the writer compressed
	// them.
	d.sendMu.Lock()
	defer d.sendMu.Unlock()
	if d.w == nil {
		d.w = getDeflater(d.level)
	}
	return true, wsQueue(ws, b0, d.w.compress(data))
}

// release returns the connection's writer, once it is gone.
func (d *wsDeflate) release() {
	d.sendMu.Lock()
	if d.w != nil {
		putDeflater(d.level, d.w)
		d.w = nil
	}
	d.sendMu.Unlock()
	d.dict, d.inflated = nil, nil
}

// inflateSrc is the input of a flate reader: a compressed message, then
// deflateTail. As an io.ByteReader it saves flate the bufio.Reader it would
// otherwise wrap it in.
type inflateSrc struct {
	p, tail []byte
}

func (r *inflateSrc) Read(b []byte) (int, error) {
	if len(r.p) == 0 {
		r.p, r.tail = r.tail, nil
		if len(r.p) == 0 {
			return 0, io.EOF
		}
	}
	n := copy(b, r.p)
	r.p = r.p[n:]
	return n, nil
}

func (r *inflateSrc) ReadByte() (byte, error) {
	if len(r.p) == 0 {
		r.p, r.tail = r.tail, nil
		if len(r.p) == 0 {
			return 0, io.EOF
		}
	}
	b := r.p[0]
	r.p = r.p[1:]
	return b, nil
}

type inflater struct {
	r   io.ReadCloser
	src inflateSrc
}

var inflaterPool = sync.Pool{New: func() any {
	f := &inflater{}
	f.r = flate.NewReader(&f.src)
	return f
}}

// inflate decompresses a received message; the result is valid until the
// next message. A non-zero code is the close code to fail the connection
// with: the message exceeds maxMessage, or is not valid DEFLATE data.
func (d *wsDeflate) inflate(p []byte, maxMessage int) ([]byte, int) {
	f := inflaterPool.Get().(*inflater)
	f.src = inflateSrc{p: p, tail: deflateTail}
	var dict []byte
	if !d.clientNoCtx {
		dict = d.dict
	}
	_ = f.r.(flate.Resetter).Reset(&f.src, dict)

	out, code := d.inflated[:0], 0
	for {
		if len(out) == cap(out) {
			out = slices.Grow(out, min(max(len(out), 4096), maxMessage+1-len(out)))
		}
		n, err := f.r.Read(out[len(out):cap(out)])
		out = out[:len(out)+n]
		if len(out) > maxMessage {
			code = CloseMessageTooBig
			break
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			code = CloseInvalidPayload
			break
		}
	}
	f.src = inflateSrc{}
	inflaterPool.Put(f)
	if cap(out) <= maxPooledBuffer {
		d.inflated = out[:0]
	} else {
		d.inflated = nil
	}
	if code != 0 {
		return nil, code
	}

	if !d.clientNoCtx {
		// The next message may refer to the last 32 KiB of this one and
		// those before.
		if len(out) >= deflateWindow {
			d.dict = append(d.dict[:0], out[len(out)-deflateWindow:]...)
		} else {
			if keep := deflateWindow - len(out); len(d.dict) > keep {
				d.dict = d.dict[:copy(d.dict, d.dict[len(d.dict)-keep:])]
			}
			d.dict = append(d.dict, out...)
		}
	}
	return out, 0
}
