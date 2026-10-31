package wisp

// The request target (RFC 9112, section 3.2): its forms, the decoding of
// the path, and query and form parameters.

import (
	"bytes"
	"net"
)

var slash = []byte("/")

// setTarget sets Path, RawPath, Query and the host of an absolute-form
// target from the request target. It returns 400 if the target is not
// valid: a target is "/path?query", "http(s)://authority/path?query", or "*"
// for OPTIONS only. Paths with percent-encoded NUL bytes or invalid
// encodings, and paths with "." or ".." segments, are refused: clients
// resolve those before sending, so only a crafted request has them, and a
// handler serving files would have to.
func (c *Ctx) setTarget(target []byte) int {
	c.host = nil
	switch {
	case target[0] == '/':
	case len(target) == 1 && target[0] == '*':
		if string(c.Method) != "OPTIONS" {
			return 400
		}
		c.Path, c.RawPath, c.Query = target, target, nil
		return 0
	default:
		rest := cutHTTPScheme(target)
		if rest == nil {
			return 400
		}
		end := len(rest)
		if i := bytes.IndexAny(rest, "/?#"); i >= 0 {
			end = i
		}
		// No userinfo in http(s) URIs (RFC 9110, section 4.2.4).
		if end == 0 || bytes.IndexByte(rest[:end], '@') >= 0 {
			return 400
		}
		c.host, target = rest[:end], rest[end:]
	}

	raw, query := target, []byte(nil)
	if i := bytes.IndexByte(target, '?'); i >= 0 {
		raw, query = target[:i], target[i+1:]
	}
	if len(raw) == 0 {
		raw = slash // "http://host" or "http://host?q"
	}
	if raw[0] != '/' {
		return 400
	}
	c.RawPath, c.Query, c.Path = raw, query, raw
	if bytes.IndexByte(raw, '%') >= 0 {
		p, ok := unescapePath(c.pathBuf[:0], raw)
		if !ok {
			return 400
		}
		c.pathBuf, c.Path = p, p
	}
	if hasDotSegment(c.Path) {
		return 400
	}
	return 0
}

// cutHTTPScheme returns what follows "http://" or "https://" (in any case),
// or nil.
func cutHTTPScheme(t []byte) []byte {
	for _, scheme := range [...]string{"http://", "https://"} {
		if len(t) > len(scheme) && equalFold(t[:len(scheme)], scheme) {
			return t[len(scheme):]
		}
	}
	return nil
}

// unescapePath appends the percent-decoded path p to dst. "%2F" is kept
// encoded, so that it does not become a segment separator; "%00" and
// malformed escapes are refused.
func unescapePath(dst, p []byte) ([]byte, bool) {
	for i := 0; i < len(p); i++ {
		if p[i] != '%' {
			dst = append(dst, p[i])
			continue
		}
		if i+2 >= len(p) {
			return dst, false
		}
		hi, lo := unhex(p[i+1]), unhex(p[i+2])
		if hi < 0 || lo < 0 {
			return dst, false
		}
		switch b := byte(hi<<4 | lo); b {
		case 0:
			return dst, false
		case '/':
			dst = append(dst, p[i:i+3]...)
		default:
			dst = append(dst, b)
		}
		i += 2
	}
	return dst, true
}

func unhex(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c - 'a' + 10)
	case c >= 'A' && c <= 'F':
		return int(c - 'A' + 10)
	}
	return -1
}

// hasDotSegment reports whether the path has a "." or ".." segment.
func hasDotSegment(p []byte) bool {
	if bytes.IndexByte(p, '.') < 0 {
		return false
	}
	for len(p) > 0 {
		p = p[1:] // the '/'
		seg := p
		if i := bytes.IndexByte(p, '/'); i >= 0 {
			seg, p = p[:i], p[i:]
		} else {
			p = nil
		}
		if string(seg) == "." || string(seg) == ".." {
			return true
		}
	}
	return false
}

// Host is the host the request is for: the authority of an absolute-form
// target, otherwise the Host header.
func (c *Ctx) Host() []byte {
	if c.host != nil {
		return c.host
	}
	return c.req.Host()
}

// RemoteAddr is the client's address, or nil outside a connection.
func (c *Ctx) RemoteAddr() net.Addr {
	if c.conn == nil {
		return nil
	}
	return c.conn.RemoteAddr()
}

// IsTLS reports whether the request came over TLS (ListenAndServeTLS).
func (c *Ctx) IsTLS() bool {
	return c.conn != nil && c.conn.isTLS()
}

// QueryParam returns the first value of the query parameter name, decoded
// ('+' is a space, "%XX" a byte), or nil if there is none. A parameter
// without '=' has an empty value. Like every []byte of a Ctx, the value is
// only valid until the handler returns.
func (c *Ctx) QueryParam(name string) []byte {
	return c.query.get(c.Query, name)
}

// VisitQuery calls fn with every query parameter, decoded, in order, until
// fn returns false.
func (c *Ctx) VisitQuery(fn func(key, value []byte) bool) {
	c.query.visit(c.Query, fn)
}

// FormParam returns the first value of the parameter name of an
// application/x-www-form-urlencoded body, decoded, or nil if there is none
// or the body is of another type.
func (c *Ctx) FormParam(name string) []byte {
	if !c.isForm() {
		return nil
	}
	return c.form.get(c.Body, name)
}

// VisitForm is VisitQuery for an application/x-www-form-urlencoded body.
func (c *Ctx) VisitForm(fn func(key, value []byte) bool) {
	if c.isForm() {
		c.form.visit(c.Body, fn)
	}
}

func (c *Ctx) isForm() bool {
	ct := c.Header("Content-Type")
	if i := bytes.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return equalFold(trimOWS(ct), MIMEApplicationForm)
}

// args are the decoded parameters of a query string or a form body,
// parsed on first use. The decoded keys and values are stored one after the
// other in buf.
type args struct {
	parsed bool
	buf    []byte
	kv     []argKV
}

type argKV struct {
	k, v, end int // key = buf[k:v], value = buf[v:end]
}

func (a *args) reset() {
	a.parsed = false
	a.buf = a.buf[:0]
	a.kv = a.kv[:0]
}

func (a *args) parse(raw []byte) {
	a.parsed = true
	for len(raw) > 0 {
		pair := raw
		if i := bytes.IndexByte(raw, '&'); i >= 0 {
			pair, raw = raw[:i], raw[i+1:]
		} else {
			raw = nil
		}
		if len(pair) == 0 {
			continue
		}
		key, value := pair, []byte(nil)
		if i := bytes.IndexByte(pair, '='); i >= 0 {
			key, value = pair[:i], pair[i+1:]
		}
		kv := argKV{k: len(a.buf)}
		a.buf = unescapeQuery(a.buf, key)
		kv.v = len(a.buf)
		a.buf = unescapeQuery(a.buf, value)
		kv.end = len(a.buf)
		a.kv = append(a.kv, kv)
	}
}

func (a *args) get(raw []byte, name string) []byte {
	if !a.parsed {
		a.parse(raw)
	}
	for _, kv := range a.kv {
		if string(a.buf[kv.k:kv.v]) == name {
			return a.buf[kv.v:kv.end:kv.end]
		}
	}
	return nil
}

func (a *args) visit(raw []byte, fn func(key, value []byte) bool) {
	if !a.parsed {
		a.parse(raw)
	}
	for _, kv := range a.kv {
		if !fn(a.buf[kv.k:kv.v:kv.v], a.buf[kv.v:kv.end:kv.end]) {
			return
		}
	}
}

// unescapeQuery appends the decoded s to dst: '+' is a space and "%XX" a
// byte; a malformed escape is kept as it is.
func unescapeQuery(dst, s []byte) []byte {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '+':
			dst = append(dst, ' ')
		case '%':
			if i+2 < len(s) {
				if hi, lo := unhex(s[i+1]), unhex(s[i+2]); hi >= 0 && lo >= 0 {
					dst = append(dst, byte(hi<<4|lo))
					i += 2
					continue
				}
			}
			dst = append(dst, c)
		default:
			dst = append(dst, c)
		}
	}
	return dst
}
