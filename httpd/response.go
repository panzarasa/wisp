package httpd

import (
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

var statusTexts = map[int]string{
	200: "OK",
	201: "Created",
	202: "Accepted",
	204: "No Content",
	301: "Moved Permanently",
	302: "Found",
	303: "See Other",
	304: "Not Modified",
	307: "Temporary Redirect",
	308: "Permanent Redirect",
	400: "Bad Request",
	401: "Unauthorized",
	403: "Forbidden",
	404: "Not Found",
	405: "Method Not Allowed",
	409: "Conflict",
	413: "Content Too Large",
	422: "Unprocessable Content",
	426: "Upgrade Required",
	429: "Too Many Requests",
	431: "Request Header Fields Too Large",
	500: "Internal Server Error",
	501: "Not Implemented",
	503: "Service Unavailable",
	505: "HTTP Version Not Supported",
}

// statusLines[code] is the full status line of the codes in statusTexts.
var statusLines [600]string

func init() {
	for code, text := range statusTexts {
		statusLines[code] = "HTTP/1.1 " + strconv.Itoa(code) + " " + text + "\r\n"
	}
}

func statusText(status int) string {
	if text, ok := statusTexts[status]; ok {
		return text
	}
	return "Status " + strconv.Itoa(status)
}

func appendStatusLine(b []byte, status int) []byte {
	if status >= 0 && status < len(statusLines) && statusLines[status] != "" {
		return append(b, statusLines[status]...)
	}

	b = append(b, "HTTP/1.1 "...)
	b = strconv.AppendInt(b, int64(status), 10)
	b = append(b, " Status "...)
	b = strconv.AppendInt(b, int64(status), 10)
	return append(b, "\r\n"...)
}

// The Date header only changes once per second, so it is formatted by a
// single goroutine and shared by every event loop.
var (
	dateOnce  sync.Once
	dateValue atomic.Pointer[[]byte]
)

func storeDate(now time.Time) {
	b := now.UTC().AppendFormat(make([]byte, 0, 32), "Mon, 02 Jan 2006 15:04:05 GMT")
	dateValue.Store(&b)
}

func httpDate() []byte {
	dateOnce.Do(func() {
		storeDate(time.Now())
		go func() {
			for now := range time.Tick(time.Second) {
				storeDate(now)
			}
		}()
	})
	return *dateValue.Load()
}
