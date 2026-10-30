package wildcat

import (
	"bytes"
	"testing"
)

func mustParse(t *testing.T, input string) (*HTTPParser, int) {
	t.Helper()

	hp := NewHTTPParser()
	n, err := hp.Parse([]byte(input))
	if err != nil {
		t.Fatalf("Parse(%q): %v", input, err)
	}
	return hp, n
}

func wantBytes(t *testing.T, what string, got []byte, want string) {
	t.Helper()

	if string(got) != want {
		t.Errorf("%s = %q, want %q", what, got, want)
	}
}

// Ported from the upstream test suite.

var simple = []byte("GET / HTTP/1.0\r\n\r\n")

func TestParseSimple(t *testing.T) {
	hp, n := mustParse(t, string(simple))

	if n != len(simple) {
		t.Errorf("n = %d, want %d", n, len(simple))
	}
	wantBytes(t, "Version", hp.Version, "HTTP/1.0")
	wantBytes(t, "Path", hp.Path, "/")
	wantBytes(t, "Method", hp.Method, "GET")
}

var simpleHeaders = []byte("GET / HTTP/1.0\r\nHost: cookie.com\r\n\r\n")

func TestParseSimpleHeaders(t *testing.T) {
	hp, _ := mustParse(t, string(simpleHeaders))

	wantBytes(t, "Host", hp.FindHeader([]byte("Host")), "cookie.com")
}

var simple3Headers = []byte("GET / HTTP/1.0\r\nHost: cookie.com\r\nDate: foobar\r\nAccept: these/that\r\n\r\n")

func TestParseSimple3Headers(t *testing.T) {
	hp, _ := mustParse(t, string(simple3Headers))

	wantBytes(t, "Host", hp.FindHeader([]byte("Host")), "cookie.com")
	wantBytes(t, "Date", hp.FindHeader([]byte("Date")), "foobar")
	wantBytes(t, "Accept", hp.FindHeader([]byte("Accept")), "these/that")
}

func TestParseMissingData(t *testing.T) {
	// Every strict prefix of a valid request is "need more data".
	hp := NewHTTPParser()
	for i := 0; i < len(simple3Headers); i++ {
		if _, err := hp.Parse(simple3Headers[:i]); err != ErrMissingData {
			t.Fatalf("Parse(%q) err = %v, want ErrMissingData", simple3Headers[:i], err)
		}
	}
}

func TestParseMultilineHeader(t *testing.T) {
	hp, _ := mustParse(t, "GET / HTTP/1.0\r\nHost: cookie.com\r\n  more host\r\n\r\n")

	wantBytes(t, "Host", hp.FindHeader([]byte("Host")), "cookie.com more host")
}

var specialHeaders = "GET / HTTP/1.0\r\nHost: cookie.com\r\nContent-Length: 50\r\n\r\n"

func TestParseSpecialHeaders(t *testing.T) {
	hp, _ := mustParse(t, specialHeaders)

	wantBytes(t, "Host()", hp.Host(), "cookie.com")
	if cl := hp.ContentLength(); cl != 50 {
		t.Errorf("ContentLength() = %d, want 50", cl)
	}
}

func TestFindHeaderIgnoresCase(t *testing.T) {
	hp, _ := mustParse(t, specialHeaders)

	wantBytes(t, "content-length", hp.FindHeader([]byte("content-length")), "50")
}

func TestFindAllHeaders(t *testing.T) {
	hp, _ := mustParse(t, "GET / HTTP/1.0\r\nBar: foo\r\nBar: quz\r\n\r\n")

	bar := []byte("Bar")

	wantBytes(t, "Bar", hp.FindHeader(bar), "foo")

	all := hp.FindAllHeaders(bar)
	if len(all) != 2 || string(all[0]) != "foo" || string(all[1]) != "quz" {
		t.Errorf("FindAllHeaders = %q, want [foo quz]", all)
	}
}

// Behaviour that differs from upstream.

func TestParseReturnsBodyOffset(t *testing.T) {
	req := "POST /echo HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello"
	_, n := mustParse(t, req)

	if req[n:] != "hello" {
		t.Errorf("body = %q, want %q", req[n:], "hello")
	}
}

func TestParserReuseResetsState(t *testing.T) {
	hp := NewHTTPParser()

	if _, err := hp.Parse([]byte("POST /a HTTP/1.1\r\nHost: one\r\nContent-Length: 7\r\nX-Only-First: 1\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	wantBytes(t, "Host()", hp.Host(), "one")
	if cl := hp.ContentLength(); cl != 7 {
		t.Fatalf("ContentLength() = %d, want 7", cl)
	}

	if _, err := hp.Parse([]byte("GET /b HTTP/1.1\r\nHost: two\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	wantBytes(t, "Host()", hp.Host(), "two")
	if cl := hp.ContentLength(); cl != -1 {
		t.Errorf("ContentLength() = %d, want -1", cl)
	}
	if v := hp.FindHeader([]byte("X-Only-First")); v != nil {
		t.Errorf("header of the previous request is still visible: %q", v)
	}
	if len(hp.Headers) != 1 {
		t.Errorf("len(Headers) = %d, want 1", len(hp.Headers))
	}
}

func TestParseMoreHeadersThanInitialSlice(t *testing.T) {
	var req bytes.Buffer
	req.WriteString("GET / HTTP/1.1\r\n")
	for i := 0; i < 3*DefaultHeaderSlice; i++ {
		req.WriteString("X-H: v\r\n")
	}
	req.WriteString("Last: yes\r\n\r\n")

	hp, n := mustParse(t, req.String())

	if n != req.Len() {
		t.Errorf("n = %d, want %d", n, req.Len())
	}
	if len(hp.Headers) != 3*DefaultHeaderSlice+1 {
		t.Errorf("len(Headers) = %d, want %d", len(hp.Headers), 3*DefaultHeaderSlice+1)
	}
	wantBytes(t, "Last", hp.FindHeader([]byte("Last")), "yes")
}

func TestParseHeaderValues(t *testing.T) {
	hp, _ := mustParse(t, "GET / HTTP/1.1\r\nEmpty:\r\nEmptyLF:\nSpaces:   a b  \t\r\nNoSpace:x\r\nHost: h\r\n\r\n")

	for name, want := range map[string]string{
		"Empty":   "",
		"EmptyLF": "",
		"Spaces":  "a b",
		"NoSpace": "x",
		"Host":    "h",
	} {
		v := hp.FindHeader([]byte(name))
		if v == nil {
			t.Errorf("header %s not found", name)
			continue
		}
		wantBytes(t, name, v, want)
	}
	if len(hp.Headers) != 5 {
		t.Errorf("len(Headers) = %d, want 5", len(hp.Headers))
	}
}

func TestParseBadProto(t *testing.T) {
	for _, req := range []string{
		"GET / HTTP/1.1\r\n folded before any header\r\n\r\n", // panicked upstream
		"GET / HTTP/1.1\r\nNoColon\r\nHost: h\r\n\r\n",
		"GET / HTTP/1.1\r\nContent-Length : 5\r\n\r\n",
		"GET / HTTP/1.1\rX\n\r\n",
		"GET / HTTP/1.1\r\nHost: h\rX\n\r\n",
		"GET / HTTP/1.1\r\nHost: h\r\n\rX",
		"GARBAGE\r\n\r\n",
		"GET /\r\n\r\n",
	} {
		hp := NewHTTPParser()
		if _, err := hp.Parse([]byte(req)); err != ErrBadProto {
			t.Errorf("Parse(%q) err = %v, want ErrBadProto", req, err)
		}
	}
}

func TestContentLengthStrict(t *testing.T) {
	for value, want := range map[string]int64{
		"0":                    0,
		"42":                   42,
		"+5":                   -1,
		"-5":                   -1,
		"0x10":                 -1,
		"5, 5":                 -1,
		"9999999999999999999":  -1,
		"99999999999999999999": -1,
	} {
		hp, _ := mustParse(t, "POST / HTTP/1.1\r\nContent-Length: "+value+"\r\n\r\n")
		if cl := hp.ContentLength(); cl != want {
			t.Errorf("Content-Length %q: got %d, want %d", value, cl, want)
		}
	}
}

func TestParseDoesNotAllocate(t *testing.T) {
	hp := NewHTTPParser()

	allocs := testing.AllocsPerRun(100, func() {
		if _, err := hp.Parse(simple3Headers); err != nil {
			t.Fatal(err)
		}
		_ = hp.Host()
		_ = hp.ContentLength()
	})
	if allocs != 0 {
		t.Errorf("allocs per Parse = %v, want 0", allocs)
	}
}

// A request like the ones bombardier sends.
var typical = []byte("GET /users/42 HTTP/1.1\r\nUser-Agent: fasthttp\r\nHost: 127.0.0.1:8080\r\n\r\n")

func BenchmarkParseSimple(b *testing.B) {
	hp := NewHTTPParser()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		hp.Parse(simple)
	}
}

func BenchmarkParseSimple3Headers(b *testing.B) {
	hp := NewHTTPParser()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		hp.Parse(simple3Headers)
	}
}

func BenchmarkParseTypical(b *testing.B) {
	hp := NewHTTPParser()

	b.ReportAllocs()
	b.SetBytes(int64(len(typical)))
	for i := 0; i < b.N; i++ {
		hp.Parse(typical)
	}
}
