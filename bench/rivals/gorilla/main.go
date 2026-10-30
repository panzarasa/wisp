// Command gorilla is the reference for the WebSocket benchmarks:
// gorilla/websocket on net/http, with the same two endpoints as cmd/server.
// Like the other rivals it lives in the bench/rivals module, so that wisp
// does not depend on any of them.
//
//   - /ws/echo sends every message back, copying it from the reader to the
//     writer without a buffer of its own (as gorilla's Autobahn server does);
//   - /ws/chat sends every text message to everyone connected: each member
//     has a writer goroutine fed by a channel, as in gorilla's chat example,
//     and a member whose channel is full is dropped.
package main

import (
	"flag"
	"io"
	"log"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	flag.Int("loops", 0, "ignored: net/http has no event loops (GOMAXPROCS follows the CPUs the process may use)")
	maxMessage := flag.Int64("ws-max-message", 1<<20, "largest WebSocket message accepted, in bytes")
	flag.Parse()

	upgrader := websocket.Upgrader{
		ReadBufferSize:  4096,
		WriteBufferSize: 4096,
	}

	http.HandleFunc("/ws/echo", func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		c.SetReadLimit(*maxMessage)
		for {
			typ, rd, err := c.NextReader()
			if err != nil {
				return
			}
			wr, err := c.NextWriter(typ)
			if err != nil {
				return
			}
			if _, err := io.Copy(wr, rd); err != nil {
				return
			}
			if err := wr.Close(); err != nil {
				return
			}
		}
	})

	h := &hub{members: map[*member]struct{}{}}
	http.HandleFunc("/ws/chat", func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		c.SetReadLimit(*maxMessage)
		m := &member{conn: c, send: make(chan []byte, 256)}
		h.add(m)
		go m.writer()
		for {
			typ, msg, err := c.ReadMessage()
			if err != nil {
				break
			}
			if typ == websocket.TextMessage {
				h.broadcast(msg)
			}
		}
		h.remove(m)
	})

	log.Printf("gorilla/websocket listening on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}

type member struct {
	conn *websocket.Conn
	send chan []byte
}

func (m *member) writer() {
	defer m.conn.Close()
	for msg := range m.send {
		if err := m.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
			return
		}
	}
}

type hub struct {
	mu      sync.Mutex
	members map[*member]struct{}
}

func (h *hub) add(m *member) {
	h.mu.Lock()
	h.members[m] = struct{}{}
	h.mu.Unlock()
}

func (h *hub) remove(m *member) {
	h.mu.Lock()
	if _, ok := h.members[m]; ok {
		delete(h.members, m)
		close(m.send)
	}
	h.mu.Unlock()
}

func (h *hub) broadcast(msg []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for m := range h.members {
		select {
		case m.send <- msg:
		default:
			delete(h.members, m)
			close(m.send)
		}
	}
}
