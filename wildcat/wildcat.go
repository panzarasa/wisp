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
//   - a folded line before the first header returned a panic (index -1), it
//     is now ErrBadProto;
//   - a header line without ':' or with whitespace before ':' is ErrBadProto,
//     as is a line break inside the method or the path. Upstream swallowed the
//     following lines into the name;
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

const (
	eNextHeader int = iota
	eNextHeaderN
	eHeader
	eHeaderValueSpace
	eHeaderValue
	eHeaderValueN
	eMLHeaderStart
	eMLHeaderValue
)

// Parse the buffer as an HTTP Request. The buffer must contain the entire
// request or Parse will return ErrMissingData for the caller to get more
// data. (this thusly favors getting a completed request in a single Read()
// call).
//
// Returns the number of bytes used by the header (thus where the body begins).
func (hp *HTTPParser) Parse(input []byte) (int, error) {
	hp.Headers = hp.Headers[:0]
	hp.host, hp.hostRead = nil, false
	hp.contentLength, hp.contentLengthRead = -1, false

	var headers int
	var path int
	var ok bool

	total := len(input)

method:
	for i := 0; i < total; i++ {
		switch input[i] {
		case ' ', '\t':
			hp.Method = input[0:i]
			ok = true
			path = i + 1
			break method
		case '\r', '\n':
			return 0, ErrBadProto
		}
	}

	if !ok {
		return 0, ErrMissingData
	}

	var version int

	ok = false

path:
	for i := path; i < total; i++ {
		switch input[i] {
		case ' ', '\t':
			ok = true
			hp.Path = input[path:i]
			version = i + 1
			break path
		case '\r', '\n':
			return 0, ErrBadProto
		}
	}

	if !ok {
		return 0, ErrMissingData
	}

	var readN bool

	ok = false
loop:
	for i := version; i < total; i++ {
		c := input[i]

		switch readN {
		case false:
			switch c {
			case '\r':
				hp.Version = input[version:i]
				readN = true
			case '\n':
				hp.Version = input[version:i]
				headers = i + 1
				ok = true
				break loop
			}
		case true:
			if c != '\n' {
				return 0, ErrBadProto
			}
			headers = i + 1
			ok = true
			break loop
		}
	}

	if !ok {
		return 0, ErrMissingData
	}

	var headerName []byte

	state := eNextHeader

	start := headers

	for i := headers; i < total; i++ {
		c := input[i]

		switch state {
		case eNextHeader:
			switch c {
			case '\r':
				state = eNextHeaderN
			case '\n':
				return i + 1, nil
			case ' ', '\t':
				if len(hp.Headers) == 0 {
					return 0, ErrBadProto
				}
				state = eMLHeaderStart
			default:
				start = i
				state = eHeader
			}
		case eNextHeaderN:
			if c != '\n' {
				return 0, ErrBadProto
			}

			return i + 1, nil
		case eHeader:
			switch c {
			case ':':
				headerName = input[start:i]
				state = eHeaderValueSpace
			case ' ', '\t', '\r', '\n':
				return 0, ErrBadProto
			}
		case eHeaderValueSpace:
			if c == ' ' || c == '\t' {
				continue
			}

			start = i
			state = eHeaderValue
			fallthrough
		case eHeaderValue:
			switch c {
			case '\r':
				state = eHeaderValueN
			case '\n':
				state = eNextHeader
			default:
				continue
			}

			hp.Headers = append(hp.Headers, Header{headerName, trimRight(input[start:i])})
		case eHeaderValueN:
			if c != '\n' {
				return 0, ErrBadProto
			}
			state = eNextHeader

		case eMLHeaderStart:
			if c == ' ' || c == '\t' {
				continue
			}

			start = i
			state = eMLHeaderValue
			fallthrough
		case eMLHeaderValue:
			switch c {
			case '\r':
				state = eHeaderValueN
			case '\n':
				state = eNextHeader
			default:
				continue
			}

			last := &hp.Headers[len(hp.Headers)-1]
			cont := trimRight(input[start:i])

			newheader := make([]byte, 0, len(last.Value)+1+len(cont))
			newheader = append(newheader, last.Value...)
			newheader = append(newheader, ' ')
			newheader = append(newheader, cont...)

			last.Value = newheader
		}
	}

	return 0, ErrMissingData
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
