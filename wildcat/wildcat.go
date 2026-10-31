// Package wildcat is an embedded copy of the HTTP request parser from
// github.com/evanphx/wildcat (http.go at commit e7012f6, 2014-11-14).
//
// Only the parser is kept: the upstream net/http glue (server, response,
// reverse proxy, body reader) is not needed on top of gnet. The parser scans
// a buffer and records sub-slices of it, so it performs no allocations on the
// hot path; every []byte it exposes aliases the input passed to Parse.
//
// Differences from upstream:
//
//   - no dependency on github.com/vektra/errors (stdlib errors instead);
//   - Parse resets the parser, so one parser can be reused for every request
//     of a keep-alive connection. Upstream kept the headers and the cached
//     Host/Content-Length of the previous request visible;
//   - Headers holds exactly the headers of the last request (len == count)
//     instead of a fixed-size slice plus TotalHeaders;
//   - the request line and the headers are validated (see Parse): upstream
//     accepted control bytes, any version string, tabs as separators, header
//     lines without ':' (swallowing the following lines into the name) and
//     folded lines, which it joined with an allocation and which panicked
//     before the first header. All of these are ErrBadProto now;
//   - empty header values ("X-Foo:\r\n") parse as empty instead of "\r" or the
//     next line, and trailing whitespace is trimmed from values;
//   - ContentLength only accepts plain decimal digits.
//
// Original license (BSD 2-Clause):
//
//	Copyright (c) 2014, Evan Phoenix
//	All rights reserved.
//
//	Redistribution and use in source and binary forms, with or without
//	modification, are permitted provided that the following conditions are met:
//
//	* Redistributions of source code must retain the above copyright notice, this
//	  list of conditions and the following disclaimer.
//
//	* Redistributions in binary form must reproduce the above copyright notice,
//	  this list of conditions and the following disclaimer in the documentation
//	  and/or other materials provided with the distribution.
//
//	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
//	AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
//	IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//	DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
//	FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
//	DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//	SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
//	CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
//	OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
//	OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
package wildcat

import (
	"bytes"
	"errors"
)

const OptimalBufferSize = 1500

type Header struct {
	Name  []byte
	Value []byte
}

type HTTPParser struct {
	Method, Path, Version []byte

	// Headers of the last parsed request, in wire order.
	Headers []Header

	host     []byte
	hostRead bool

	contentLength     int64
	contentLengthRead bool
}

const DefaultHeaderSlice = 10

// Create a new parser
func NewHTTPParser() *HTTPParser {
	return NewSizedHTTPParser(DefaultHeaderSlice)
}

// Create a new parser allocating size for size headers
func NewSizedHTTPParser(size int) *HTTPParser {
	return &HTTPParser{
		Headers:       make([]Header, 0, size),
		contentLength: -1,
	}
}

var (
	ErrBadProto    = errors.New("bad protocol")
	ErrMissingData = errors.New("missing data")
	ErrUnsupported = errors.New("unsupported http feature")
)

// tchar marks the bytes allowed in a token (RFC 9110, section 5.6.2): methods
// and header names.
var tchar = func() (t [256]bool) {
	for c := '0'; c <= '9'; c++ {
		t[c] = true
	}
	for c := 'a'; c <= 'z'; c++ {
		t[c], t[c-'a'+'A'] = true, true
	}
	for _, c := range "!#$%&'*+-.^_`|~" {
		t[c] = true
	}
	return t
}()

// fieldByte marks the bytes allowed in a header value (RFC 9110, section
// 5.5): visible ASCII, space, tab and obs-text. Control bytes are not.
var fieldByte = func() (t [256]bool) {
	for c := 0x20; c < 0x100; c++ {
		t[c] = c != 0x7F
	}
	t['\t'] = true
	return t
}()

// Parse the buffer as an HTTP Request. The buffer must contain the entire
// request or Parse will return ErrMissingData for the caller to get more
// data. (this thusly favors getting a completed request in a single Read()
// call).
//
// The request line and the headers are validated (RFC 9112): the method is a
// token followed by one space; the request target has no control bytes and
// is followed by one space; the version is "HTTP/" DIGIT "." DIGIT; header
// names are tokens directly followed by ':'; header values have no control
// bytes but tab; lines end with CRLF, or a bare LF. Anything else, including
// obsolete line folding, is ErrBadProto. Every strict prefix of a valid
// request is ErrMissingData.
//
// Returns the number of bytes used by the header (thus where the body begins).
func (hp *HTTPParser) Parse(input []byte) (int, error) {
	hp.Method, hp.Path, hp.Version = nil, nil, nil
	hp.Headers = hp.Headers[:0]
	hp.host, hp.hostRead = nil, false
	hp.contentLength, hp.contentLengthRead = -1, false

	total := len(input)
	i := 0

	// method SP
	for i < total && tchar[input[i]] {
		i++
	}
	if i == total {
		return 0, ErrMissingData
	}
	if i == 0 || input[i] != ' ' {
		return 0, ErrBadProto
	}
	hp.Method = input[:i]
	i++

	// request-target SP
	start := i
	for i < total && input[i] > ' ' && input[i] != 0x7F {
		i++
	}
	if i == total {
		return 0, ErrMissingData
	}
	if i == start || input[i] != ' ' {
		return 0, ErrBadProto
	}
	hp.Path = input[start:i]
	i++

	// HTTP-version = "HTTP/" DIGIT "." DIGIT
	start = i
	for k := 0; k < len("HTTP/1.1"); k++ {
		if i == total {
			return 0, ErrMissingData
		}
		c := input[i]
		var ok bool
		switch k {
		case 5, 7:
			ok = c >= '0' && c <= '9'
		case 6:
			ok = c == '.'
		default:
			ok = c == "HTTP/"[k]
		}
		if !ok {
			return 0, ErrBadProto
		}
		i++
	}
	hp.Version = input[start:i]

	i, err := lineEnd(input, i)
	if err != nil {
		return 0, err
	}

	for {
		if i == total {
			return 0, ErrMissingData
		}
		if c := input[i]; c == '\r' || c == '\n' {
			// The empty line that ends the header.
			return lineEnd(input, i)
		}

		// field-name ":" OWS field-value OWS
		start := i
		for i < total && tchar[input[i]] {
			i++
		}
		if i == total {
			return 0, ErrMissingData
		}
		// A line that starts with whitespace is an obsolete folded
		// continuation of the previous one: rejected (RFC 9112, section 5.2).
		if i == start || input[i] != ':' {
			return 0, ErrBadProto
		}
		name := input[start:i]
		i++

		for i < total && (input[i] == ' ' || input[i] == '\t') {
			i++
		}
		start = i
		for i < total && fieldByte[input[i]] {
			i++
		}
		value := trimRight(input[start:i])

		if i, err = lineEnd(input, i); err != nil {
			return 0, err
		}
		hp.Headers = append(hp.Headers, Header{name, value})
	}
}

// lineEnd returns the offset after the line ending at input[i]: CRLF or a
// bare LF.
func lineEnd(input []byte, i int) (int, error) {
	switch {
	case i == len(input):
		return 0, ErrMissingData
	case input[i] == '\n':
		return i + 1, nil
	case input[i] != '\r':
		return 0, ErrBadProto
	case i+1 == len(input):
		return 0, ErrMissingData
	case input[i+1] != '\n':
		return 0, ErrBadProto
	}
	return i + 2, nil
}

func trimRight(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == ' ' || b[len(b)-1] == '\t') {
		b = b[:len(b)-1]
	}
	return b
}

// Return a value of a header matching name.
func (hp *HTTPParser) FindHeader(name []byte) []byte {
	for _, header := range hp.Headers {
		if bytes.Equal(header.Name, name) {
			return header.Value
		}
	}

	for _, header := range hp.Headers {
		if bytes.EqualFold(header.Name, name) {
			return header.Value
		}
	}

	return nil
}

// Return all values of a header matching name.
func (hp *HTTPParser) FindAllHeaders(name []byte) [][]byte {
	var headers [][]byte

	for _, header := range hp.Headers {
		if bytes.EqualFold(header.Name, name) {
			headers = append(headers, header.Value)
		}
	}

	return headers
}

var cHost = []byte("Host")

// Return the value of the Host header
func (hp *HTTPParser) Host() []byte {
	if hp.hostRead {
		return hp.host
	}

	hp.hostRead = true
	hp.host = hp.FindHeader(cHost)
	return hp.host
}

var cContentLength = []byte("Content-Length")

// Return the value of the Content-Length header.
// A value of -1 indicates the header was not set or is not a decimal number.
func (hp *HTTPParser) ContentLength() int64 {
	if hp.contentLengthRead {
		return hp.contentLength
	}

	if header := hp.FindHeader(cContentLength); header != nil {
		hp.contentLength = ParseDecimal(header)
	}

	hp.contentLengthRead = true
	return hp.contentLength
}

// ParseDecimal parses b as an unsigned decimal number made only of ASCII
// digits. It returns -1 if b is empty, has any other byte or overflows.
func ParseDecimal(b []byte) int64 {
	if len(b) == 0 || len(b) > 18 {
		return -1
	}

	var n int64
	for _, c := range b {
		if c < '0' || c > '9' {
			return -1
		}
		n = n*10 + int64(c-'0')
	}

	return n
}

var cGet = []byte("GET")

func (hp *HTTPParser) Get() bool {
	return bytes.Equal(hp.Method, cGet)
}

var cPost = []byte("POST")

func (hp *HTTPParser) Post() bool {
	return bytes.Equal(hp.Method, cPost)
}
