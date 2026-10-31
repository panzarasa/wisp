package wisp

// The WebSocket wire format (RFC 6455, section 5) and the pieces of the
// protocol that do not depend on a connection: frame encoding, masking,
// close payloads, the handshake key and streaming UTF-8 validation.

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
)

// Opcodes (RFC 6455, section 5.2).
const (
	opContinuation = 0x0
	opText         = 0x1
	opBinary       = 0x2
	opClose        = 0x8
	opPing         = 0x9
	opPong         = 0xA
)

// Close status codes (RFC 6455, section 7.4.1).
const (
	CloseNormal          = 1000
	CloseGoingAway       = 1001
	CloseProtocolError   = 1002
	CloseUnsupportedData = 1003
	CloseNoStatus        = 1005 // never sent: the peer's close frame had no code
	CloseAbnormal        = 1006 // never sent: the connection ended without a close frame
	CloseInvalidPayload  = 1007
	ClosePolicyViolation = 1008
	CloseMessageTooBig   = 1009
	CloseInternalError   = 1011
)

// maxControlPayload is the largest payload of a control frame, and of a
// close frame in particular: 2 bytes of code plus at most 123 of reason.
const maxControlPayload = 125

// validCloseCode reports whether code may appear in a close frame: the codes
// defined by RFC 6455 and registered with IANA since, plus the ranges for
// libraries (3000-3999) and applications (4000-4999).
func validCloseCode(code int) bool {
	switch {
	case code >= 1000 && code <= 1003:
		return true
	case code >= 1007 && code <= 1014:
		return true
	case code >= 3000 && code <= 4999:
		return true
	}
	return false
}

// appendFrameHeader appends the header of an unmasked frame with a payload
// of n bytes (servers never mask, section 5.1); b0 is its first byte: FIN,
// RSV1 and the opcode.
func appendFrameHeader(b []byte, b0 byte, n int) []byte {
	switch {
	case n < 126:
		return append(b, b0, byte(n))
	case n <= 0xFFFF:
		return append(b, b0, 126, byte(n>>8), byte(n))
	default:
		b = append(b, b0, 127)
		return binary.BigEndian.AppendUint64(b, uint64(n))
	}
}

// appendClosePayload appends the payload of a close frame: the code, then
// the reason.
func appendClosePayload(b []byte, code int, reason string) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(code))
	return append(b, reason...)
}

// parseClosePayload decodes the payload of a received close frame. A
// non-zero failure is the close code the connection must be failed with.
func parseClosePayload(p []byte) (code int, reason []byte, failure int) {
	switch {
	case len(p) == 0:
		return CloseNoStatus, nil, 0
	case len(p) == 1:
		return 0, nil, CloseProtocolError
	}
	code = int(binary.BigEndian.Uint16(p))
	if !validCloseCode(code) {
		return 0, nil, CloseProtocolError
	}
	if utf8Feed(utf8Accept, p[2:]) != utf8Accept {
		return 0, nil, CloseInvalidPayload
	}
	return code, p[2:], 0
}

// unmask XORs p in place with the masking key (section 5.3), eight bytes at
// a time.
func unmask(p []byte, key []byte) {
	k32 := binary.LittleEndian.Uint32(key)
	k64 := uint64(k32)<<32 | uint64(k32)
	i := 0
	for ; i+8 <= len(p); i += 8 {
		binary.LittleEndian.PutUint64(p[i:], binary.LittleEndian.Uint64(p[i:])^k64)
	}
	// i is a multiple of 8, so the key is still aligned with i.
	for ; i < len(p); i++ {
		p[i] ^= key[i&3]
	}
}

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// wsAcceptKey computes Sec-WebSocket-Accept for a Sec-WebSocket-Key
// (section 4.2.2, item 5.4).
func wsAcceptKey(dst *[28]byte, key []byte) {
	var buf [24 + len(wsGUID)]byte
	n := copy(buf[:], key)
	n += copy(buf[n:], wsGUID)
	sum := sha1.Sum(buf[:n])
	base64.StdEncoding.Encode(dst[:], sum[:])
}

// validWSKey reports whether key is the base64 encoding of 16 bytes
// (section 4.1, item 7).
func validWSKey(key []byte) bool {
	if len(key) != 24 {
		return false
	}
	var raw [18]byte
	n, err := base64.StdEncoding.Decode(raw[:], key)
	return err == nil && n == 16
}

// utf8State is the state of a streaming UTF-8 validator, for text messages
// that arrive in fragments: a code point may be split across two of them,
// and an invalid one must fail the connection as soon as it is seen
// (section 8.1).
type utf8State uint8

const (
	utf8Accept utf8State = iota // between code points
	utf8Cont1                   // one continuation byte (80-BF) missing
	utf8Cont2                   // two missing
	utf8Cont3                   // three missing
	utf8E0                      // after E0: A0-BF, then one more
	utf8ED                      // after ED: 80-9F (no surrogates), then one more
	utf8F0                      // after F0: 90-BF, then two more
	utf8F4                      // after F4: 80-8F (up to U+10FFFF), then two more
	utf8Reject
)

// utf8Feed advances the validator over p (RFC 3629, section 4).
func utf8Feed(s utf8State, p []byte) utf8State {
	for i := 0; i < len(p); i++ {
		b := p[i]
		switch s {
		case utf8Accept:
			switch {
			case b < 0x80:
			case b < 0xC2:
				return utf8Reject
			case b < 0xE0:
				s = utf8Cont1
			case b == 0xE0:
				s = utf8E0
			case b == 0xED:
				s = utf8ED
			case b < 0xF0:
				s = utf8Cont2
			case b == 0xF0:
				s = utf8F0
			case b < 0xF4:
				s = utf8Cont3
			case b == 0xF4:
				s = utf8F4
			default:
				return utf8Reject
			}
		case utf8Cont1, utf8Cont2, utf8Cont3:
			if b&0xC0 != 0x80 {
				return utf8Reject
			}
			s--
		case utf8E0:
			if b < 0xA0 || b > 0xBF {
				return utf8Reject
			}
			s = utf8Cont1
		case utf8ED:
			if b < 0x80 || b > 0x9F {
				return utf8Reject
			}
			s = utf8Cont1
		case utf8F0:
			if b < 0x90 || b > 0xBF {
				return utf8Reject
			}
			s = utf8Cont2
		case utf8F4:
			if b < 0x80 || b > 0x8F {
				return utf8Reject
			}
			s = utf8Cont2
		default:
			return utf8Reject
		}
	}
	return s
}
