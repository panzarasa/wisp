// Command baseline is gnet alone: no request parsing and no routing. It is
// the reference the HTTP layer of cmd/server is measured against.
//
// The only thing it knows about HTTP is that a request without a body ends
// with an empty line, which it needs to send one response per request. Every
// request, whatever its method or path, gets the same pre-built response,
// byte for byte the one cmd/server sends for "GET /".
package main

import (
	"bytes"
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/panjf2000/gnet/v2"
)

const body = "Hello, World!"

var (
	endOfRequest = []byte("\r\n\r\n")

	// The whole response, rebuilt once per second because of the Date header.
	response atomic.Pointer[[]byte]
)

func buildResponse(now time.Time) {
	b := []byte("HTTP/1.1 200 OK\r\nServer: wisp\r\nDate: ")
	b = now.UTC().AppendFormat(b, "Mon, 02 Jan 2006 15:04:05 GMT")
	b = append(b, "\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 13\r\n\r\n"...)
	b = append(b, body...)
	response.Store(&b)
}

type baseline struct {
	gnet.BuiltinEventEngine
	engine atomic.Pointer[gnet.Engine]
}

func (s *baseline) OnBoot(eng gnet.Engine) gnet.Action {
	s.engine.Store(&eng)
	return gnet.None
}

func (s *baseline) OnTraffic(c gnet.Conn) gnet.Action {
	buf, _ := c.Peek(-1)

	requests, consumed := 0, 0
	for {
		i := bytes.Index(buf[consumed:], endOfRequest)
		if i < 0 {
			break
		}
		consumed += i + len(endOfRequest)
		requests++
	}

	// Discard(0) would drop the whole buffer.
	if consumed > 0 {
		_, _ = c.Discard(consumed)
	}

	resp := *response.Load()
	for ; requests > 0; requests-- {
		if _, err := c.Write(resp); err != nil {
			return gnet.Close
		}
	}
	return gnet.None
}

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	loops := flag.Int("loops", 0, "number of event loops (0 = one per CPU)")
	flag.Parse()

	buildResponse(time.Now())
	go func() {
		for now := range time.Tick(time.Second) {
			buildResponse(now)
		}
	}()

	srv := &baseline{}

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if eng := srv.engine.Load(); eng != nil {
			_ = eng.Stop(ctx)
		}
	}()

	opts := []gnet.Option{gnet.WithMulticore(true)}
	if *loops > 0 {
		opts = []gnet.Option{gnet.WithNumEventLoop(*loops)}
	}

	if !strings.Contains(*addr, "://") {
		*addr = "tcp://" + *addr
	}
	log.Printf("gnet baseline listening on %s", *addr)
	if err := gnet.Run(srv, *addr, opts...); err != nil {
		log.Fatal(err)
	}
}
