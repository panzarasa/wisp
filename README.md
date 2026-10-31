# wisp

A small HTTP/1.1 server for Go with WebSocket (RFC 6455) on the same port,
built on [gnet](https://github.com/panjf2000/gnet) event loops instead of a
goroutine per connection.

- Requests are parsed in place by an embedded copy of the
  [wildcat](https://github.com/evanphx/wildcat) parser: no allocations on the
  hot path. Parsing is strict (RFC 9112): control characters, malformed
  methods, versions and header names, folded headers, a missing or repeated
  `Host`, and `Transfer-Encoding` together with `Content-Length` are refused.
- Routing with static segments, `:param` and `*wildcard`, middleware, route
  groups and trailing-slash redirects. Paths are percent-decoded; query and
  form parameters are decoded on demand.
- Keep-alive and pipelining, chunked request bodies, `Expect: 100-continue`,
  and bodies too large to buffer streamed to the handler piece by piece.
- `Ctx.Async` runs a slow handler on a goroutine pool without blocking the
  event loop; responses keep the order of pipelined requests.
- Timeouts against slow and idle clients, a cap on unread responses, and a
  graceful `Shutdown` that waits for the requests in flight.
- HTTPS with `crypto/tls`, served by the same HTTP and WebSocket code.
- `Ctx.Upgrade` turns the connection into a WebSocket. The frames travel on
  the same gnet connection, so an open WebSocket costs about 1 KB of memory.
  permessage-deflate (RFC 7692), streaming of large messages in both
  directions.
- The [Autobahn TestSuite](https://github.com/crossbario/autobahn-testsuite)
  passes with no failures (`autobahn/run.sh`); the compression cases (12.*,
  13.*) are now enabled too.

## Example

```go
package main

import (
	"log"
	"time"

	"github.com/panjf2000/gnet/v2"

	"github.com/panzarasa/wisp"
)

func logger(next wisp.Handler) wisp.Handler {
	return func(c *wisp.Ctx) {
		start := time.Now()
		next(c)
		log.Printf("%s %s %v", c.Method, c.Path, time.Since(start))
	}
}

func main() {
	r := wisp.NewRouter()
	r.Use(logger)

	r.GET("/", func(c *wisp.Ctx) {
		c.Text(200, "Hello, World!")
	})

	api := r.Group("/api")
	api.GET("/users/:id", func(c *wisp.Ctx) {
		c.Bytes(200, wisp.MIMETextPlain, append([]byte("user "), c.Param("id")...))
	})
	api.GET("/report", func(c *wisp.Ctx) {
		// Blocking work: off the event loop.
		c.Async(func(c *wisp.Ctx) {
			time.Sleep(100 * time.Millisecond) // a database, another service...
			c.Text(200, "report for "+string(c.QueryParam("year")))
		})
	})

	echo := &wisp.WSHandler{
		Compression: &wisp.WSCompression{},
		OnMessage: func(ws *wisp.WSConn, typ wisp.WSMessageType, data []byte) {
			ws.Send(typ, data)
		},
	}
	r.GET("/ws/echo", func(c *wisp.Ctx) {
		c.Upgrade(echo)
	})

	srv := &wisp.Server{Handler: r.Serve}
	go func() {
		log.Fatal(srv.ListenAndServeTLS(":8443", "cert.pem", "key.pem"))
	}()
	log.Fatal(srv.ListenAndServe(":8080", gnet.WithMulticore(true), gnet.WithReuseAddr(true)))
}
```

`cmd/server` is a complete example, with a chat room (open `/chat` in two
tabs), TLS flags and graceful shutdown.

## Handlers

Handlers run on the event loops. A handler that blocks stalls every
connection on its loop: it calls `c.Async(fn)`, and `fn` runs on a pool of
goroutines (at most `Server.MaxAsync` at once, 503 beyond) with its own copy
of the request. The requests a client pipelines behind it wait for its
response.

Every `[]byte` a `Ctx` returns (`Path`, `Param`, `Header`, `Body`,
`QueryParam`...) points into the connection's buffers and is valid only until
the handler returns.

Bodies up to `Server.MaxBodyBytes` (4 MiB) are buffered and handed over whole
in `c.Body`. A larger `Content-Length` goes to `Server.StreamHandler`, which
can take the body piece by piece with `c.ReceiveBody(&wisp.BodyStream{...})`.

## Timeouts and limits

| `Server` field | default | |
|---|---:|---|
| `ReadHeaderTimeout` | 10 s | first byte of a request to the end of its header; also the TLS handshake (slowloris) |
| `ReadTimeout` | 60 s | first byte of a request to the end of its body |
| `WriteTimeout` | 30 s | how long responses may wait for a client that does not read |
| `IdleTimeout` | 60 s | keep-alive connection waiting for its next request |
| `MaxHeaderBytes` | 64 KiB | 431 beyond |
| `MaxBodyBytes` | 4 MiB | 413 beyond, or `StreamHandler` |
| `MaxOutboundBytes` | 4 MiB | unread responses; past it pipelined requests stay unread |
| `MaxAsync` | 10 000 | handlers running with `Async` |

A request that times out gets a 408. A negative timeout disables it. The
checks run as often as the shortest timeout needs, so sub-second timeouts
work, for WebSocket connections too.

`Shutdown(ctx)` stops accepting, closes idle connections, lets the requests
in flight finish (their responses carry `Connection: close`), sends a 1001
close frame to WebSocket peers, and returns once all are gone or `ctx`
expires.

## TLS

gnet has no TLS, so HTTPS follows the design of
[maurice2k/tcpserver](https://github.com/maurice2k/tcpserver):

- `wisp.Listen` sets `SO_REUSEPORT`, and on Linux `TCP_FASTOPEN` and
  `TCP_DEFER_ACCEPT`, so the server only wakes up once the client's first
  bytes (the ClientHello) have arrived.
- Several goroutines accept on the listener (`Server.TLSAcceptLoops`), and each
  connection is handed to a pool of goroutines and wrapped with `tls.Server`.

From there on, a TLS connection behaves like a gnet connection: a reader
goroutine turns what it decrypts into events, a writer goroutine sends the
responses, and the HTTP and WebSocket code is the same. `ListenAndServeTLS`
loads a certificate pair; `ServeTLS(ln, config)` takes any `tls.Config`.
`c.IsTLS()` tells the two apart. ALPN offers `http/1.1`.

## WebSocket

- `WSHandler.Compression` enables permessage-deflate for clients that offer
  it. By default every message is compressed on its own, so the flate state
  comes from pools and an idle connection keeps none of it.
  `ContextTakeover: true` compresses better but keeps a compressor per
  connection.
- `WSConn.NextWriter(typ)` sends a message as a series of frames, for
  messages too large to build in memory.
- `WSHandler.OnFrame` receives each frame as it arrives instead of whole
  messages; `MaxMessageBytes` then limits a frame.
- Idle peers are pinged, then dropped (`IdleTimeout`); `Send` can be called
  from any goroutine.

## Not supported yet

- HTTP/2
- transfer codings other than `chunked`; chunked bodies larger than
  `MaxBodyBytes` (only `Content-Length` bodies can be streamed)

## Benchmarks

These figures were measured before the release that added timeouts, TLS,
`Async` and compression; the hot path barely changed (parsing a request got
faster, a WebSocket frame costs 2 ns more).

Every server runs on **one core** (one event loop for wisp). The load
generator runs on three other cores of the same machine, over loopback, so
it never competes with the server for CPU. Each case is a fresh server,
warmed up, then 10 seconds of load. The tables show the median of the
repetitions: 5 for HTTP, 3 for WebSocket.

The setup is:

- **Machine:** Apple M4, macOS 15.7, Docker in a colima VM (4 vCPU, Linux 6.8,
  arm64).
- **Software:** Go 1.26.
- **HTTP rivals:** Fiber v3.6.1 with its default settings, and fasthttp
  v1.77.0 with the path matched by hand, its fastest form.
- **WebSocket rival:** gorilla/websocket v1.5.3 on net/http.

All servers send the same responses, and no errors occurred in any run. The
VM adds noise, sometimes 10-30% on a single repetition, so read small
differences with care.

### HTTP

Load is generated by [bombardier](https://github.com/codesenberg/bombardier).
Each connection sends a request and waits for the response.

| request | conns | wisp | Fiber | fasthttp | wisp vs best rival |
|---|---:|---:|---:|---:|---:|
| `GET /` | 16 | **262k req/s** | 205k | 207k | +27% |
| `GET /` | 64 | **269k** | 192k | 194k | +38% |
| `GET /` | 256 | **264k** | 185k | 159k | +43% |
| `GET /` | 1024 | **231k** | 169k | 173k | +34% |
| `GET /users/:id` | 256 | **248k** | 190k | 203k | +23% |
| `POST /echo`, 1 KiB | 256 | **240k** | 174k | 183k | +31% |

Latency, in µs, as p50 / p99:

| request | conns | wisp | Fiber | fasthttp |
|---|---:|---:|---:|---:|
| `GET /` | 16 | 53 / 171 | 75 / 187 | 72 / 200 |
| `GET /` | 64 | 211 / 632 | 296 / 1394 | 287 / 1412 |
| `GET /` | 256 | 896 / 1988 | 1277 / 5122 | 1320 / 6486 |
| `GET /` | 1024 | 4135 / 9263 | 5968 / 9639 | 5849 / 8068 |
| `GET /users/:id` | 256 | 918 / 2932 | 1324 / 2561 | 1242 / 2329 |
| `POST /echo` | 256 | 995 / 2146 | 1455 / 2403 | 1381 / 2309 |

Each server answers as fast as it can, so wisp serves 25-40% more requests
than the others in the same time. That favours it at the median and burdens
it at the tail. Where its p99 is higher, it is carrying more load.

Peak server memory was 5-10 MiB for wisp, 5-23 MiB for fasthttp and 8-26 MiB
for Fiber.

### WebSocket

Load is generated by `cmd/wsload`.

**Echo of 128-byte messages at a fixed rate.** This is the fair latency
comparison: both servers get exactly the same load, sent evenly.

| rate | conns | wisp p50 / p99 | gorilla p50 / p99 | CPU wisp / gorilla |
|---|---:|---:|---:|---:|
| 100k msg/s | 64 | 27 / 49 µs | 24 / 49 µs | 0.56 / 0.64 |
| 100k msg/s | 256 | 27 / 47 µs | 24 / 50 µs | 0.56 / 0.64 |
| 300k msg/s | 64 | 16 / **39 µs** | 14 / 160 µs | 0.86 / 0.97 |
| 300k msg/s | 256 | 16 / **44 µs** | 13 / 543 µs | 0.87 / 0.98 |

**Maximum throughput.** Each connection sends and waits for the echo, except
in the pipelined case.

| case | wisp | gorilla | |
|---|---:|---:|---:|
| echo 128 B, 16 conns | **455k msg/s** | 396k | +15% |
| echo 128 B, 64 conns | **453k** | 394k | +15% |
| echo 128 B, 256 conns | **459k** | 382k | +20% |
| echo 128 B, 1024 conns | **435k** | 330k | +32% |
| echo 128 B, 64 conns, 16 in flight each | **5.60M** | 0.53M | 10.5× |
| echo 16 KiB, 64 conns | **179k (2.9 GB/s)** | 72k (1.2 GB/s) | 2.5× |

**Chat room.** One sender; every 64-byte message goes to all members.

| members | wisp | gorilla | wisp p99 | gorilla p99 |
|---:|---:|---:|---:|---:|
| 100 | **6.2M deliveries/s** | 0.62M | 0.3 ms | 2.6 ms |
| 1 000 | **7.2M** | 0.60M | 2.4 ms | 26.5 ms |
| 5 000 | **4.8M** | 0.51M | 17.9 ms | 158.9 ms |

With 100 and 1 000 members wisp does not use its whole core: the load
generator is the limit there, so those figures are a floor.

**Idle connections.** These are server memory figures: each connection is
open and has exchanged one message.

| conns | wisp | gorilla |
|---:|---:|---:|
| 1 000 | 6 MiB | 31 MiB |
| 10 000 | 16 MiB | 252 MiB |
| 50 000 | **55 MiB (1.0 KB/conn)** | 1 234 MiB (25.8 KB/conn) |

### Reproduce

You need Docker; on macOS, `colima start`.

```sh
bench/bench.sh      # HTTP, about 25 minutes; medians in bench/results/summary.txt
bench/wsbench.sh    # WebSocket, about 20 minutes; bench/results-ws/summary.txt
```

`REPS=1 DURATION=3s` gives a quick look. The scripts list the other
parameters.

## Layout

```
*.go             package wisp: server, router, WebSocket, TLS (tls.go), MIME constants (mime.go)
wildcat/         embedded HTTP request parser (BSD 2-Clause, see wildcat/LICENSE)
cmd/server       example server, also the benchmark target
cmd/baseline     gnet alone, as a reference for the HTTP layer's cost
cmd/wsload       WebSocket load generator
bench/           benchmark scripts and image; bench/rivals: Fiber, fasthttp, gorilla
autobahn/        RFC 6455 conformance run
```

## License

wisp is licensed under the [GNU Affero General Public License v3.0](LICENSE).
You may use it, change it and sell it. If you distribute it, or let people use
it over a network, you must release your source code under the same license,
changes included.

The exception is `wildcat/`, an embedded copy of
[evanphx/wildcat](https://github.com/evanphx/wildcat). It keeps its own
BSD 2-Clause license (`wildcat/LICENSE`).
