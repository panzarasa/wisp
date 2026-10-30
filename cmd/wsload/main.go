// Command wsload is the WebSocket load generator of the benchmarks in bench/
// (bombardier only speaks HTTP). It is a minimal RFC 6455 client, enough to
// drive /ws/echo and /ws/chat, plus the measurements: message rate, latency
// percentiles and, with -server-pid on Linux, the CPU time and memory of the
// server process over the same window.
//
//	wsload -mode echo -conns 256 -size 128 -d 10s    request/response
//	wsload -mode echo -conns 256 -rate 300000         fixed pace (open loop)
//	wsload -mode idle -conns 10000 -d 5s              memory per connection
//	wsload -mode chat -conns 1000 -size 64 -d 10s     broadcast fan-out
//	wsload -summary results.jsonl                     table of a whole run
//
// Each run prints one JSON line (see result) on stdout.
package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type config struct {
	addr        string
	mode        string
	target      string
	rep         int
	conns       int
	size        int
	pipeline    int
	rate        float64
	window      int
	duration    time.Duration
	warmup      time.Duration
	serverPID   int
	dialWorkers int
	srcIPs      int
	dump        string
	pacers      int
}

// result is one run. Latencies are in microseconds; memory in KiB.
type result struct {
	Target   string `json:"target"`
	Mode     string `json:"mode"`
	Rep      int    `json:"rep"`
	Conns    int    `json:"conns"`
	Size     int    `json:"size"`
	Pipeline int    `json:"pipeline,omitempty"`
	Window   int    `json:"window,omitempty"`
	// TargetRate: messages per second asked for, in echo at a fixed pace.
	TargetRate float64 `json:"target_rate,omitempty"`

	Seconds float64 `json:"seconds"`
	// Messages: echoes received (echo) or deliveries to members (chat).
	Messages  uint64  `json:"messages"`
	Published uint64  `json:"published,omitempty"`
	Rate      float64 `json:"rate"`
	P50       float64 `json:"p50_us"`
	P90       float64 `json:"p90_us"`
	P99       float64 `json:"p99_us"`
	P999      float64 `json:"p999_us"`
	Max       float64 `json:"max_us"`

	ConnectSeconds float64 `json:"connect_seconds,omitempty"`
	Failed         int     `json:"failed"`

	ServerCPU      float64 `json:"server_cpu_seconds"`
	ServerRSSStart int     `json:"server_rss_start_kb"`
	ServerRSSEnd   int     `json:"server_rss_end_kb"`
	ServerHWM      int     `json:"server_hwm_kb"`
	BytesPerConn   float64 `json:"bytes_per_conn,omitempty"`
}

func main() {
	var cfg config
	summary := flag.String("summary", "", "print the table of a results.jsonl file and exit")
	flag.StringVar(&cfg.addr, "addr", "127.0.0.1:8080", "server address")
	flag.StringVar(&cfg.mode, "mode", "echo", "echo, idle or chat")
	flag.StringVar(&cfg.target, "target", "", "name of the server under test, copied to the result")
	flag.IntVar(&cfg.rep, "rep", 0, "repetition number, copied to the result")
	flag.IntVar(&cfg.conns, "conns", 64, "connections")
	flag.IntVar(&cfg.size, "size", 128, "message size in bytes")
	flag.IntVar(&cfg.pipeline, "pipeline", 1, "echo: messages each connection sends before reading the echoes")
	flag.Float64Var(&cfg.rate, "rate", 0, "echo: send this many messages per second in all, whatever the echoes do (0 = request/response)")
	flag.IntVar(&cfg.window, "window", 16, "chat: messages in flight (not yet delivered to every member)")
	flag.DurationVar(&cfg.duration, "d", 10*time.Second, "measured duration")
	flag.DurationVar(&cfg.warmup, "warmup", 2*time.Second, "load before the measured window (echo, chat)")
	flag.IntVar(&cfg.serverPID, "server-pid", 0, "server process, for CPU and memory (Linux /proc)")
	flag.IntVar(&cfg.dialWorkers, "dial-workers", 128, "connections opened in parallel")
	flag.IntVar(&cfg.srcIPs, "src-ips", 1, "local addresses 127.0.0.1..127.0.0.N, for more than ~28000 connections")
	flag.IntVar(&cfg.pacers, "pacers", 0, "echo at a fixed pace: send from this many goroutines that busy-wait for each message's time, one OS thread each, instead of one timer-driven goroutine per connection (smooth load, but each pacer takes a whole CPU)")
	flag.StringVar(&cfg.dump, "dump", "", "echo at a fixed pace: write every measured message to this CSV file (send time and latency in ns, connection)")
	flag.Parse()
	log.SetFlags(0)
	log.SetPrefix("wsload: ")

	if *summary != "" {
		if err := printSummary(*summary); err != nil {
			log.Fatal(err)
		}
		return
	}
	if cfg.size < 32 {
		log.Fatal("-size must be at least 32")
	}

	var (
		res *result
		err error
	)
	switch cfg.mode {
	case "echo":
		if cfg.rate > 0 {
			res, err = runEchoRate(&cfg)
		} else {
			res, err = runEcho(&cfg)
		}
	case "idle":
		res, err = runIdle(&cfg)
	case "chat":
		res, err = runChat(&cfg)
	default:
		err = fmt.Errorf("unknown -mode %q", cfg.mode)
	}
	if err != nil {
		log.Fatal(err)
	}
	res.Target, res.Mode, res.Rep, res.Conns, res.Size = cfg.target, cfg.mode, cfg.rep, cfg.conns, cfg.size
	out, _ := json.Marshal(res)
	fmt.Println(string(out))

	// One line for whoever watches the run.
	if cfg.mode == "idle" {
		fmt.Fprintf(os.Stderr, "%-8s idle c=%-6d  opened in %.2fs  RSS %.1f MiB  %.0f byte/conn  CPU %.3f\n",
			res.Target, res.Conns, res.ConnectSeconds, float64(res.ServerRSSEnd)/1024, res.BytesPerConn, res.ServerCPU/res.Seconds)
	} else {
		fmt.Fprintf(os.Stderr, "%-8s %-4s c=%-6d size=%-6d %10.0f msg/s  p50 %6.0f  p99 %6.0f us  CPU %.2f\n",
			res.Target, res.Mode, res.Conns, res.Size, res.Rate, res.P50, res.P99, res.ServerCPU/res.Seconds)
	}
}

// ---- echo -------------------------------------------------------------------

// runEcho: every connection sends -pipeline binary messages, waits for the
// echoes, and starts over. The latency of a message is the time from the
// write of its batch to the read of its echo.
func runEcho(cfg *config) (*result, error) {
	conns, connectTime, err := connectAll(cfg, "/ws/echo")
	if err != nil {
		return nil, err
	}
	defer closeAll(conns)

	payload := make([]byte, cfg.size)
	for i := range payload {
		payload[i] = byte('a' + i%26)
	}
	var batch []byte
	for range cfg.pipeline {
		batch = appendClientFrame(batch, opBinary, payload)
	}

	start := time.Now()
	measureFrom := start.Add(cfg.warmup)
	end := measureFrom.Add(cfg.duration)

	hists := make([]*histogram, len(conns))
	counts := make([]uint64, len(conns))
	errs := make([]error, len(conns))
	var wg sync.WaitGroup
	for i, c := range conns {
		hists[i] = newHistogram()
		wg.Go(func() {
			h := hists[i]
			for {
				t0 := time.Now()
				if !t0.Before(end) {
					return
				}
				if _, err := c.c.Write(batch); err != nil {
					errs[i] = err
					return
				}
				for range cfg.pipeline {
					op, p, err := c.readFrame()
					if err != nil {
						errs[i] = err
						return
					}
					if op != opBinary || len(p) != cfg.size {
						errs[i] = fmt.Errorf("unexpected echo: opcode %d, %d bytes", op, len(p))
						return
					}
				}
				if !t0.Before(measureFrom) {
					lat := time.Since(t0)
					for range cfg.pipeline {
						h.record(lat)
					}
					counts[i] += uint64(cfg.pipeline)
				}
			}
		})
	}

	sleepUntil(measureFrom)
	srv := sampleServer(cfg.serverPID)
	sleepUntil(end)
	res := srv.finish(cfg.serverPID)
	wg.Wait()

	res.Pipeline = cfg.pipeline
	res.ConnectSeconds = connectTime.Seconds()
	res.Seconds = cfg.duration.Seconds()
	total := newHistogram()
	for i := range conns {
		if errs[i] != nil {
			return nil, fmt.Errorf("connection %d: %w", i, errs[i])
		}
		total.merge(hists[i])
		res.Messages += counts[i]
	}
	res.Rate = float64(res.Messages) / res.Seconds
	total.fill(res)
	return res, nil
}

// runEchoRate: open loop. Every connection sends rate/conns messages per
// second, whatever the echoes do, so both servers see the same load and their
// latencies can be compared (in request/response the faster server also gets
// more load, and the client's own queuing grows with it). Each message
// carries the time it was written; its latency runs from there to the read of
// its echo. By default the writers wake on Go timers, which are coarse: what
// is due goes out in one write, every connection out of phase with the
// others, and the load comes in bursts. With -pacers the messages go out one
// by one at their time, from goroutines that busy-wait.
func runEchoRate(cfg *config) (*result, error) {
	conns, connectTime, err := connectAll(cfg, "/ws/echo")
	if err != nil {
		return nil, err
	}
	defer closeAll(conns)

	n := len(conns)
	interval := time.Duration(float64(time.Second) * float64(n) / cfg.rate)
	epoch := time.Now()
	fromNS := cfg.warmup
	endNS := cfg.warmup + cfg.duration

	hists := make([]*histogram, n)
	counts := make([]uint64, n)
	samples := make([][][2]int64, n)
	sent := make([]atomic.Uint64, n)
	received := make([]atomic.Uint64, n)
	errs := make([]error, 2*n)
	stop := make(chan struct{})
	var writers, readers sync.WaitGroup
	for p := range cfg.pacers {
		// Pacer p sends to connections p, p+pacers, ... in turn.
		writers.Go(func() {
			runtime.LockOSThread()
			payload := make([]byte, cfg.size)
			var frame []byte
			every := time.Duration(float64(time.Second) * float64(cfg.pacers) / cfg.rate)
			due := every * time.Duration(p) / time.Duration(cfg.pacers)
			for j := p; due < endNS; due += every {
				for time.Since(epoch) < due {
				}
				binary.LittleEndian.PutUint64(payload, uint64(time.Since(epoch)))
				frame = appendClientFrame(frame[:0], opBinary, payload)
				if _, err := conns[j].c.Write(frame); err != nil {
					errs[j] = err
					return
				}
				sent[j].Add(1)
				if j += cfg.pacers; j >= n {
					j = p
				}
			}
		})
	}
	for i, c := range conns {
		hists[i] = newHistogram()
		if cfg.pacers == 0 {
			writers.Go(func() {
				payload := make([]byte, cfg.size)
				var frame []byte
				due := interval * time.Duration(i) / time.Duration(n)
				for due < endNS {
					if wait := due - time.Since(epoch); wait > 0 {
						time.Sleep(wait)
					}
					now := time.Since(epoch)
					binary.LittleEndian.PutUint64(payload, uint64(now))
					frame = frame[:0]
					k := uint64(0)
					for ; due <= now && due < endNS; due += interval {
						frame = appendClientFrame(frame, opBinary, payload)
						k++
					}
					if _, err := c.c.Write(frame); err != nil {
						errs[i] = err
						return
					}
					sent[i].Add(k)
				}
			})
		}
		readers.Go(func() {
			h := hists[i]
			for {
				op, p, err := c.readFrame()
				if err != nil {
					select {
					case <-stop:
					default:
						errs[n+i] = err
					}
					return
				}
				now := time.Since(epoch)
				if op != opBinary || len(p) != cfg.size {
					errs[n+i] = fmt.Errorf("unexpected echo: opcode %d, %d bytes", op, len(p))
					return
				}
				if t := time.Duration(binary.LittleEndian.Uint64(p)); t >= fromNS {
					h.record(now - t)
					counts[i]++
					if cfg.dump != "" {
						samples[i] = append(samples[i], [2]int64{int64(t), int64(now - t)})
					}
				}
				received[i].Add(1)
			}
		})
	}

	sleepUntil(epoch.Add(fromNS))
	srv := sampleServer(cfg.serverPID)
	sleepUntil(epoch.Add(endNS))
	res := srv.finish(cfg.serverPID)
	writers.Wait()

	// Wait for the last echoes.
	var totalSent uint64
	for i := range n {
		totalSent += sent[i].Load()
	}
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
		var got uint64
		for i := range n {
			got += received[i].Load()
		}
		if got == totalSent {
			break
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("%d of %d echoes still missing after 10s", totalSent-got, totalSent)
		}
	}
	close(stop)
	closeAll(conns)
	readers.Wait()

	if cfg.dump != "" {
		if err := writeSamples(cfg.dump, samples); err != nil {
			return nil, err
		}
	}

	res.TargetRate = cfg.rate
	res.ConnectSeconds = connectTime.Seconds()
	res.Seconds = cfg.duration.Seconds()
	total := newHistogram()
	for i := range 2 * n {
		if errs[i] != nil {
			return nil, fmt.Errorf("connection %d: %w", i%n, errs[i])
		}
	}
	for i := range n {
		total.merge(hists[i])
		res.Messages += counts[i]
	}
	res.Rate = float64(res.Messages) / res.Seconds
	total.fill(res)
	return res, nil
}

func writeSamples(path string, samples [][][2]int64) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	fmt.Fprintln(w, "sent_ns,latency_ns,conn")
	for i, ss := range samples {
		for _, s := range ss {
			fmt.Fprintf(w, "%d,%d,%d\n", s[0], s[1], i)
		}
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// ---- idle -------------------------------------------------------------------

// runIdle opens -conns connections, has each exchange one message (so the
// server has allocated whatever a used connection needs), then leaves them
// idle for -d. The memory per connection is the growth of the server's RSS
// divided by the connections; the CPU time is what the server spends on
// idle connections (timers, pings).
func runIdle(cfg *config) (*result, error) {
	before := readMem(cfg.serverPID)
	conns, connectTime, err := connectAll(cfg, "/ws/echo")
	if err != nil {
		return nil, err
	}
	defer closeAll(conns)

	payload := make([]byte, cfg.size)
	frame := appendClientFrame(nil, opBinary, payload)
	errs := make(chan error, len(conns))
	sem := make(chan struct{}, cfg.dialWorkers)
	for _, c := range conns {
		sem <- struct{}{}
		go func() {
			defer func() { <-sem }()
			if _, err := c.c.Write(frame); err != nil {
				errs <- err
				return
			}
			if _, _, err := c.readFrame(); err != nil {
				errs <- err
				return
			}
			// Idle connections keep nothing on the client but the socket.
			c.r, c.buf = nil, nil
		}()
	}
	for range cap(sem) {
		sem <- struct{}{}
	}
	close(errs)
	if err := <-errs; err != nil {
		return nil, err
	}

	// Give the server a moment to finish what the last messages started.
	time.Sleep(time.Second)
	srv := sampleServer(cfg.serverPID)
	time.Sleep(cfg.duration)
	res := srv.finish(cfg.serverPID)
	res.ServerRSSStart = before.rss
	res.ConnectSeconds = connectTime.Seconds()
	res.Seconds = cfg.duration.Seconds()
	if cfg.serverPID > 0 {
		res.BytesPerConn = float64(res.ServerRSSEnd-before.rss) * 1024 / float64(len(conns))
	}
	return res, nil
}

// ---- chat -------------------------------------------------------------------

// runChat connects -conns members to /ws/chat. Member 0 publishes text
// messages carrying their sequence number and send time; every member,
// publisher included, receives each of them. At most -window messages are
// in flight: message n is sent only once n-window has reached everyone. The
// latency of a delivery is from the publish to the read by that member.
func runChat(cfg *config) (*result, error) {
	conns, connectTime, err := connectAll(cfg, "/ws/chat")
	if err != nil {
		return nil, err
	}
	defer closeAll(conns)
	// The upgrade response may reach the client before the server has
	// registered the member (gorilla answers first, then registers).
	time.Sleep(200 * time.Millisecond)

	w := cfg.window
	pending := make([]atomic.Int32, w)
	done := make([]chan struct{}, w)
	for i := range done {
		done[i] = make(chan struct{}, 1)
	}

	epoch := time.Now()
	measureFrom := epoch.Add(cfg.warmup)
	end := measureFrom.Add(cfg.duration)
	fromNS := int64(cfg.warmup)

	n := int32(len(conns))
	hists := make([]*histogram, len(conns))
	counts := make([]uint64, len(conns))
	errs := make([]error, len(conns))
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i, c := range conns {
		hists[i] = newHistogram()
		wg.Go(func() {
			h := hists[i]
			for {
				op, p, err := c.readFrame()
				if err != nil {
					select {
					case <-stop:
					default:
						errs[i] = err
					}
					return
				}
				if op != opText || len(p) != cfg.size {
					errs[i] = fmt.Errorf("unexpected message: opcode %d, %d bytes", op, len(p))
					return
				}
				now := int64(time.Since(epoch))
				seq, _ := strconv.ParseUint(string(p[:16]), 16, 64)
				sent, _ := strconv.ParseInt(string(p[16:32]), 16, 64)
				if sent >= fromNS {
					h.record(time.Duration(now - sent))
					counts[i]++
				}
				slot := seq % uint64(w)
				if pending[slot].Add(1) == n {
					done[slot] <- struct{}{}
				}
			}
		})
	}

	payload := make([]byte, cfg.size)
	for i := range payload {
		payload[i] = 'x'
	}
	pub := conns[0]
	var srv serverSample
	var published uint64
	sampled := false
	var frame []byte
	for seq := uint64(0); ; seq++ {
		slot := seq % uint64(w)
		if seq >= uint64(w) {
			select {
			case <-done[slot]:
			case <-time.After(10 * time.Second):
				return nil, fmt.Errorf("message %d not delivered to every member in 10s", seq-uint64(w))
			}
			pending[slot].Store(0)
		}
		now := time.Now()
		if !now.Before(end) {
			// Wait for the messages still in flight, so that every
			// member's counters are final.
			for m := max(seq, uint64(w)) - uint64(w) + 1; m < seq; m++ {
				select {
				case <-done[m%uint64(w)]:
				case <-time.After(10 * time.Second):
					return nil, errors.New("messages still in flight after 10s")
				}
			}
			break
		}
		if !sampled && !now.Before(measureFrom) {
			srv, sampled = sampleServer(cfg.serverPID), true
		}
		if sampled {
			published++
		}
		putHex(payload[:16], seq)
		putHex(payload[16:32], uint64(now.Sub(epoch)))
		frame = appendClientFrame(frame[:0], opText, payload)
		if _, err := pub.c.Write(frame); err != nil {
			return nil, err
		}
	}
	res := srv.finish(cfg.serverPID)
	close(stop)
	closeAll(conns)
	wg.Wait()

	res.Window = w
	res.Published = published
	res.ConnectSeconds = connectTime.Seconds()
	res.Seconds = cfg.duration.Seconds()
	total := newHistogram()
	for i := range conns {
		if errs[i] != nil {
			return nil, fmt.Errorf("member %d: %w", i, errs[i])
		}
		total.merge(hists[i])
		res.Messages += counts[i]
	}
	res.Rate = float64(res.Messages) / res.Seconds
	total.fill(res)
	return res, nil
}

// ---- connections ------------------------------------------------------------

const (
	opText   = 0x1
	opBinary = 0x2
	opClose  = 0x8
	opPing   = 0x9
	opPong   = 0xA
)

// maskKey is the same for every frame: the server unmasks whatever the key
// is, and a fixed one lets frames be built once.
var maskKey = [4]byte{0x12, 0x34, 0x56, 0x78}

type wsConn struct {
	c   net.Conn
	r   *bufio.Reader
	buf []byte
	hdr [8]byte
}

func connectAll(cfg *config, path string) ([]*wsConn, time.Duration, error) {
	start := time.Now()
	conns := make([]*wsConn, cfg.conns)
	// Idle connections only read one small echo: tens of thousands of
	// them must not cost the client 16 KiB each.
	readBuf := 16 << 10
	if cfg.mode == "idle" {
		readBuf = 1024
	}
	var (
		next   atomic.Int64
		failed atomic.Int64
		first  atomic.Value
		wg     sync.WaitGroup
	)
	for range min(cfg.dialWorkers, cfg.conns) {
		wg.Go(func() {
			for {
				i := int(next.Add(1) - 1)
				if i >= cfg.conns {
					return
				}
				d := net.Dialer{Timeout: 10 * time.Second}
				if cfg.srcIPs > 1 {
					d.LocalAddr = &net.TCPAddr{IP: net.IPv4(127, 0, 0, byte(1+i%cfg.srcIPs))}
				}
				c, err := dial(&d, cfg.addr, path, readBuf)
				if err != nil {
					failed.Add(1)
					first.CompareAndSwap(nil, err)
					return
				}
				conns[i] = c
			}
		})
	}
	wg.Wait()
	if n := failed.Load(); n > 0 {
		closeAll(conns)
		return nil, 0, fmt.Errorf("%d of %d connections failed, the first with: %v", n, cfg.conns, first.Load())
	}
	return conns, time.Since(start), nil
}

func closeAll(conns []*wsConn) {
	for _, c := range conns {
		if c != nil {
			c.c.Close()
		}
	}
}

func dial(d *net.Dialer, addr, path string, readBuf int) (*wsConn, error) {
	c, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + addr + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if _, err := io.WriteString(c, req); err != nil {
		c.Close()
		return nil, err
	}
	r := bufio.NewReaderSize(c, readBuf)
	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		c.Close()
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols ||
		resp.Header.Get("Sec-WebSocket-Accept") != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		c.Close()
		return nil, fmt.Errorf("handshake refused: %s", resp.Status)
	}
	return &wsConn{c: c, r: r}, nil
}

// appendClientFrame appends a final, masked frame.
func appendClientFrame(b []byte, op byte, payload []byte) []byte {
	n := len(payload)
	switch {
	case n < 126:
		b = append(b, 0x80|op, 0x80|byte(n))
	case n <= 0xFFFF:
		b = append(b, 0x80|op, 0x80|126, byte(n>>8), byte(n))
	default:
		b = append(b, 0x80|op, 0x80|127)
		b = binary.BigEndian.AppendUint64(b, uint64(n))
	}
	b = append(b, maskKey[:]...)
	for i, x := range payload {
		b = append(b, x^maskKey[i&3])
	}
	return b
}

// readFrame returns the next message, reassembled if the server fragmented
// it (gorilla does, past its write buffer); the payload is valid until the
// next call. Pings are answered; a close frame is an error.
func (c *wsConn) readFrame() (byte, []byte, error) {
	var (
		msgOp byte
		msgN  int
	)
	for {
		h := c.hdr[:2]
		if _, err := io.ReadFull(c.r, h); err != nil {
			return 0, nil, err
		}
		if h[0]&0x70 != 0 || h[1]&0x80 != 0 {
			return 0, nil, fmt.Errorf("unexpected frame header %x", h)
		}
		fin := h[0]&0x80 != 0
		op := h[0] & 0x0F
		n := int(h[1] & 0x7F)
		switch n {
		case 126:
			if _, err := io.ReadFull(c.r, c.hdr[:2]); err != nil {
				return 0, nil, err
			}
			n = int(binary.BigEndian.Uint16(c.hdr[:2]))
		case 127:
			if _, err := io.ReadFull(c.r, c.hdr[:8]); err != nil {
				return 0, nil, err
			}
			n = int(binary.BigEndian.Uint64(c.hdr[:8]))
		}
		if op >= opClose {
			// Control frames come whole, and may arrive between the
			// fragments of a message.
			var ctl [125]byte
			if n > len(ctl) || !fin {
				return 0, nil, fmt.Errorf("invalid control frame header %x", h)
			}
			p := ctl[:n]
			if _, err := io.ReadFull(c.r, p); err != nil {
				return 0, nil, err
			}
			switch op {
			case opPing:
				if _, err := c.c.Write(appendClientFrame(nil, opPong, p)); err != nil {
					return 0, nil, err
				}
			case opClose:
				code := 0
				if len(p) >= 2 {
					code = int(binary.BigEndian.Uint16(p))
				}
				return 0, nil, fmt.Errorf("closed by the server: %d %s", code, p[min(2, len(p)):])
			}
			continue
		}
		if (op == 0) != (msgOp != 0) {
			return 0, nil, fmt.Errorf("unexpected opcode %d", op)
		}
		if op != 0 {
			msgOp = op
		}
		if cap(c.buf) < msgN+n {
			c.buf = append(c.buf[:msgN], make([]byte, n)...)
		}
		if _, err := io.ReadFull(c.r, c.buf[msgN:msgN+n]); err != nil {
			return 0, nil, err
		}
		msgN += n
		if fin {
			return msgOp, c.buf[:msgN], nil
		}
	}
}

// putHex writes v in hexadecimal over the whole of dst: chat messages are
// text, so the sequence number and the send time travel as digits.
func putHex(dst []byte, v uint64) {
	for i := len(dst) - 1; i >= 0; i-- {
		dst[i] = "0123456789abcdef"[v&0xF]
		v >>= 4
	}
}

func sleepUntil(t time.Time) {
	time.Sleep(time.Until(t))
}

// ---- server process ---------------------------------------------------------

type serverSample struct {
	cpu float64
	rss int
}

type memInfo struct{ rss, hwm int }

func sampleServer(pid int) serverSample {
	return serverSample{cpu: readCPU(pid), rss: readMem(pid).rss}
}

func (s serverSample) finish(pid int) *result {
	m := readMem(pid)
	return &result{
		ServerCPU:      readCPU(pid) - s.cpu,
		ServerRSSStart: s.rss,
		ServerRSSEnd:   m.rss,
		ServerHWM:      m.hwm,
	}
}

// readCPU returns the user plus system CPU time of pid, in seconds.
func readCPU(pid int) float64 {
	if pid <= 0 {
		return 0
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	// Fields after the command name, which is in parentheses and may
	// contain spaces: state is the first, utime the 12th, stime the 13th.
	s := string(b)
	f := strings.Fields(s[strings.LastIndexByte(s, ')')+1:])
	if len(f) < 13 {
		return 0
	}
	utime, _ := strconv.ParseFloat(f[11], 64)
	stime, _ := strconv.ParseFloat(f[12], 64)
	return (utime + stime) / 100 // USER_HZ is 100 on Linux
}

func readMem(pid int) memInfo {
	var m memInfo
	if pid <= 0 {
		return m
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return m
	}
	for line := range strings.Lines(string(b)) {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "VmRSS:":
			m.rss, _ = strconv.Atoi(f[1])
		case "VmHWM:":
			m.hwm, _ = strconv.Atoi(f[1])
		}
	}
	return m
}
