package httpd

import (
	"strconv"

	"github.com/panjf2000/gnet/v2"

	"github.com/panzarasa/wisp/wildcat"
)

// Handler handles one HTTP request and writes exactly one response on ctx.
type Handler func(ctx *Ctx)

// MaxParams is the maximum number of parameters in a route pattern.
const MaxParams = 8

type param struct {
	key   string
	value []byte
}

// Ctx is the request being handled and the writer for its response.
//
// A Ctx and every []byte obtained from it (Method, Path, Query, Body, Param,
// Header) alias the connection's read buffer: they are only valid until the
// handler returns. Copy what must outlive the handler.
type Ctx struct {
	Method []byte
	Path   []byte // without the query string
	Query  []byte // raw query string, without the '?'
	Body   []byte

	req     *wildcat.HTTPParser
	srv     *Server
	conn    gnet.Conn // nil when process runs without gnet, in tests
	ws      *WSConn   // set by Upgrade
	params  [MaxParams]param
	nparams int

	out       []byte // responses of this connection waiting to be written
	respStart int    // offset in out of the response to the current request
	extra     []byte // extra response headers set by SetHeader
	responded bool
	close     bool // the connection is closed after this response
	head      bool // HEAD request: the response body is not sent
}

func (c *Ctx) reset() {
	c.respStart = len(c.out)
	c.extra = c.extra[:0]
	c.nparams = 0
	c.responded = false
	c.close = false
	c.head = false
}

// Param returns the value of a ":name" or "*name" segment of the matched
// route, or nil.
func (c *Ctx) Param(name string) []byte {
	for i := 0; i < c.nparams; i++ {
		if c.params[i].key == name {
			return c.params[i].value
		}
	}
	return nil
}

// Header returns the first request header called name (case-insensitive), or
// nil.
func (c *Ctx) Header(name string) []byte {
	for i := range c.req.Headers {
		if equalFold(c.req.Headers[i].Name, name) {
			return c.req.Headers[i].Value
		}
	}
	return nil
}

// SetHeader adds a header to the response. It must be called before the
// response is written; Content-Length, Date, Server and Connection are
// managed by the server.
func (c *Ctx) SetHeader(name, value string) {
	c.extra = append(c.extra, name...)
	c.extra = append(c.extra, ": "...)
	c.extra = append(c.extra, value...)
	c.extra = append(c.extra, "\r\n"...)
}

// Bytes writes a response. Writing again replaces the previous response.
func (c *Ctx) Bytes(status int, contentType string, body []byte) {
	if !c.writeHead(status, contentType, len(body)) {
		return
	}
	if !c.head && bodyAllowed(status) {
		c.out = append(c.out, body...)
	}
}

// String is Bytes for a string body.
func (c *Ctx) String(status int, contentType string, body string) {
	if !c.writeHead(status, contentType, len(body)) {
		return
	}
	if !c.head && bodyAllowed(status) {
		c.out = append(c.out, body...)
	}
}

// Text writes a text/plain response.
func (c *Ctx) Text(status int, body string) {
	c.String(status, "text/plain; charset=utf-8", body)
}

// JSON writes an already encoded JSON document.
func (c *Ctx) JSON(status int, body []byte) {
	c.Bytes(status, "application/json", body)
}

// Status writes a response without a body.
func (c *Ctx) Status(status int) {
	c.writeHead(status, "", 0)
}

// writeHead writes the status line and headers; it returns false after
// Upgrade, whose 101 response is final.
func (c *Ctx) writeHead(status int, contentType string, bodyLen int) bool {
	if c.ws != nil {
		return false
	}
	b := c.out[:c.respStart]

	b = appendStatusLine(b, status)
	b = append(b, "Server: wisp\r\nDate: "...)
	b = append(b, httpDate()...)
	b = append(b, "\r\n"...)
	if bodyAllowed(status) {
		if contentType != "" {
			b = append(b, "Content-Type: "...)
			b = append(b, contentType...)
			b = append(b, "\r\n"...)
		}
		b = append(b, "Content-Length: "...)
		b = strconv.AppendInt(b, int64(bodyLen), 10)
		b = append(b, "\r\n"...)
	}
	if c.close {
		b = append(b, "Connection: close\r\n"...)
	}
	b = append(b, c.extra...)
	b = append(b, "\r\n"...)

	c.out = b
	c.responded = true
	return true
}

// fail answers with an error status and closes the connection: after a
// request that cannot be framed the rest of the stream is not trustworthy.
func (c *Ctx) fail(status int) {
	c.close = true
	c.Text(status, statusText(status))
}

func bodyAllowed(status int) bool {
	return status >= 200 && status != 204 && status != 304
}

// equalFold reports whether b and s are equal ignoring ASCII case.
func equalFold(b []byte, s string) bool {
	if len(b) != len(s) {
		return false
	}
	for i := 0; i < len(b); i++ {
		x, y := b[i], s[i]
		if x == y {
			continue
		}
		if x|0x20 != y|0x20 || x|0x20 < 'a' || x|0x20 > 'z' {
			return false
		}
	}
	return true
}
