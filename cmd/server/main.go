// Command server is gnet with our HTTP layer on top: the embedded wildcat
// parser plus the httpd router. /ws/echo and /ws/chat upgrade their
// connection to WebSocket, on the same port.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/panjf2000/gnet/v2"

	"github.com/panzarasa/wisp/httpd"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	loops := flag.Int("loops", 0, "number of event loops (0 = one per CPU)")
	wsOrigins := flag.String("ws-origins", "", `comma-separated origins allowed to open a WebSocket, such as "http://localhost:8080" ("*" = any; empty = same origin only)`)
	wsMaxMessage := flag.Int("ws-max-message", httpd.DefaultWSMaxMessageBytes, "largest WebSocket message accepted, in bytes")
	flag.Parse()

	r := httpd.NewRouter()

	r.GET("/", func(c *httpd.Ctx) {
		c.Text(200, "Hello, World!")
	})

	r.GET("/users/:id", func(c *httpd.Ctx) {
		body := append(make([]byte, 0, 64), "user "...)
		body = append(body, c.Param("id")...)
		c.Bytes(200, "text/plain; charset=utf-8", body)
	})

	r.POST("/echo", func(c *httpd.Ctx) {
		contentType := "application/octet-stream"
		if v := c.Header("Content-Type"); len(v) > 0 {
			contentType = string(v)
		}
		c.Bytes(200, contentType, c.Body)
	})

	r.GET("/static/*file", func(c *httpd.Ctx) {
		c.Text(200, "file "+string(c.Param("file")))
	})

	var origins []string
	if *wsOrigins != "" {
		origins = strings.Split(*wsOrigins, ",")
	}

	echo := &httpd.WSHandler{
		AllowedOrigins:  origins,
		MaxMessageBytes: *wsMaxMessage,
		// Room for a few echoed messages to a client that reads slowly.
		MaxOutboundBytes: max(httpd.DefaultWSMaxOutboundBytes, 4**wsMaxMessage),
		OnMessage: func(ws *httpd.WSConn, typ httpd.WSMessageType, data []byte) {
			ws.Send(typ, data)
		},
	}
	r.GET("/ws/echo", func(c *httpd.Ctx) {
		c.Upgrade(echo)
	})

	// Every text message goes to everyone connected. Send can be called
	// from any event loop, so members on other loops are reached too.
	var (
		mu      sync.Mutex
		members = map[*httpd.WSConn]struct{}{}
	)
	chat := &httpd.WSHandler{
		AllowedOrigins:  origins,
		MaxMessageBytes: *wsMaxMessage,
		OnMessage: func(_ *httpd.WSConn, typ httpd.WSMessageType, data []byte) {
			if typ != httpd.WSText {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for m := range members {
				m.Send(httpd.WSText, data)
			}
		},
		OnClose: func(ws *httpd.WSConn, _ int, _ string) {
			mu.Lock()
			delete(members, ws)
			mu.Unlock()
		},
	}
	r.GET("/ws/chat", func(c *httpd.Ctx) {
		ws, err := c.Upgrade(chat)
		if err != nil {
			return
		}
		mu.Lock()
		members[ws] = struct{}{}
		mu.Unlock()
	})

	srv := &httpd.Server{Handler: r.Serve}

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Fatal(err)
		}
	}()

	// SO_REUSEADDR, as net/http has it: a restart must not wait for the
	// connections the server closed first to leave TIME_WAIT.
	opts := []gnet.Option{gnet.WithReuseAddr(true), gnet.WithMulticore(true)}
	if *loops > 0 {
		opts = []gnet.Option{gnet.WithReuseAddr(true), gnet.WithNumEventLoop(*loops)}
	}

	log.Printf("wisp listening on %s", *addr)
	if err := srv.ListenAndServe(*addr, opts...); err != nil {
		log.Fatal(err)
	}
}
