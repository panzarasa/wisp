package wisp

// Request bodies that are not a plain Content-Length: chunked bodies
// (RFC 9112, section 7.1), decoded in place once complete, and bodies too
// large to buffer, streamed to a BodyStream as they arrive.

import "bytes"

// maxChunkLine bounds a chunk-size line, extensions included.
const maxChunkLine = 4096

// chunkScan is how far a chunked body has been checked. A body is decoded
// only once it is complete, so each event that brings a part of it resumes
// where the previous one stopped instead of starting over.
type chunkScan struct {
	off     int   // offset in the body of the next chunk-size or trailer line
	size    int64 // decoded bytes before off
	trailer bool  // the last chunk is behind: off is in the trailer section
}

// scanChunked checks the chunked body at the start of body, from where sc
// left off. Once the body is complete it returns its length on the wire,
// trailer section included. While it is not, it returns 0 and, when known,
// the length body needs to have for the scan to progress. A non-zero status
// rejects the request: 400 for a malformed body, 413 for one whose decoded
// size exceeds maxBody or whose encoding exceeds maxWire.
func scanChunked(body []byte, sc *chunkScan, maxBody int64, maxWire int) (n, need, status int) {
	for {
		if sc.off > maxWire {
			return 0, 0, 413
		}
		rest := body[sc.off:]
		i := bytes.IndexByte(rest, '\n')
		if i < 0 {
			if len(rest) > maxChunkLine {
				return 0, 0, 400
			}
			return 0, 0, 0
		}
		// Bare LFs are refused here: lenient chunk parsing is a classic
		// request smuggling vector.
		if i == 0 || i > maxChunkLine || rest[i-1] != '\r' {
			return 0, 0, 400
		}
		line := rest[:i-1]

		if sc.trailer {
			if len(line) == 0 {
				return sc.off + i + 1, 0, 0
			}
			// Trailer fields are not passed on, only checked.
			if !validFieldLine(line) {
				return 0, 0, 400
			}
			sc.off += i + 1
			continue
		}

		size := chunkSize(line)
		switch {
		case size < 0:
			return 0, 0, 400
		case size == 0:
			sc.trailer = true
			sc.off += i + 1
			continue
		case size > maxBody-sc.size:
			return 0, 0, 413
		}
		end := i + 1 + int(size) + 2
		if len(rest) < end {
			return 0, sc.off + end, 0
		}
		if rest[end-2] != '\r' || rest[end-1] != '\n' {
			return 0, 0, 400
		}
		sc.size += size
		sc.off += end
	}
}

// chunkSize parses a chunk-size line: hex digits, then optional extensions
// (";name=value"), which are ignored. It returns -1 if the line is not valid.
func chunkSize(line []byte) int64 {
	var n int64
	i := 0
	for ; i < len(line); i++ {
		d := unhex(line[i])
		if d < 0 {
			break
		}
		if i == 15 {
			return -1 // more than 15 hex digits: too large
		}
		n = n<<4 | int64(d)
	}
	if i == 0 {
		return -1
	}
	ext := line[i:]
	for len(ext) > 0 && (ext[0] == ' ' || ext[0] == '\t') {
		ext = ext[1:]
	}
	if len(ext) > 0 && (ext[0] != ';' || !validFieldLine(ext)) {
		return -1
	}
	return n
}

// validFieldLine reports whether a line has no control bytes but tab.
func validFieldLine(line []byte) bool {
	for _, c := range line {
		if c < ' ' && c != '\t' || c == 0x7F {
			return false
		}
	}
	return true
}

// decodeChunked decodes a complete chunked body, checked by scanChunked, in
// place and returns its decoded length.
func decodeChunked(body []byte) int {
	w, r := 0, 0
	for {
		i := bytes.IndexByte(body[r:], '\n')
		size := int(chunkSize(body[r : r+i-1]))
		r += i + 1
		if size == 0 {
			return w
		}
		// Every chunk-size line is at least 3 bytes, so w < r.
		w += copy(body[w:], body[r:r+size])
		r += size + 2
	}
}

// BodyStream receives a request body too large to be buffered: see
// Server.StreamHandler and Ctx.ReceiveBody.
type BodyStream struct {
	// Data is called on the event loop with each piece of the body, in
	// order, as it arrives; p is only valid during the call. An error stops
	// the request: the response written on c so far, or a 500, is sent and
	// the connection closed.
	Data func(c *Ctx, p []byte) error
	// End is called once the whole body has arrived. It writes the
	// response, as a handler does.
	End func(c *Ctx)
}

// ReceiveBody accepts the body of a request passed to Server.StreamHandler:
// instead of being buffered, it will be passed to bs as it arrives. The
// request data (Method, Path, headers, Param...) becomes invalid when the
// StreamHandler returns, so copy what Data and End need. ReceiveBody does
// nothing in an ordinary Handler.
func (c *Ctx) ReceiveBody(bs *BodyStream) {
	c.bodyStream = bs
}

// feedStream passes the start of buf to the body being streamed. It returns
// how much of buf it consumed, whether the request is complete, and whether
// the connection must be closed.
func (s *Server) feedStream(st *connState, buf []byte) (n int, done, closeConn bool) {
	c := &st.ctx
	if int64(len(buf)) > st.streamLeft {
		buf = buf[:st.streamLeft]
	}
	if len(buf) > 0 {
		st.streamLeft -= int64(len(buf))
		if err := st.stream.Data(c, buf); err != nil {
			st.stream = nil
			if !c.responded {
				c.fail(500)
			}
			c.close = true
			return len(buf), true, true
		}
	}
	if st.streamLeft > 0 {
		return len(buf), false, false
	}
	bs := st.stream
	st.stream, st.headerDone = nil, false
	bs.End(c)
	if !c.responded {
		c.Status(204)
	}
	return len(buf), true, c.close
}
