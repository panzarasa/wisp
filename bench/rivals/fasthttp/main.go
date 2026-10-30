// Command fasthttp is a reference for the HTTP benchmarks: valyala/fasthttp
// with the same three routes as cmd/server and the same responses.
//
// fasthttp has no router: the handler matches the path itself, the least it
// can do, so this is fasthttp at its fastest. Fiber (bench/rivals/fiber) is
// the same server with a router and a framework on top.
package main

import (
	"bytes"
	"flag"
	"log"

	"github.com/valyala/fasthttp"
)

var usersPrefix = []byte("/users/")

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	flag.Int("loops", 0, "ignored: fasthttp has no event loops (GOMAXPROCS follows the CPUs the process may use)")
	flag.Parse()

	handler := func(ctx *fasthttp.RequestCtx) {
		path := ctx.Path()
		switch {
		case ctx.IsGet() && string(path) == "/":
			ctx.SetContentType("text/plain; charset=utf-8")
			ctx.SetBodyString("Hello, World!")
		case ctx.IsGet() && bytes.HasPrefix(path, usersPrefix) && len(path) > len(usersPrefix) &&
			bytes.IndexByte(path[len(usersPrefix):], '/') < 0:
			ctx.SetContentType("text/plain; charset=utf-8")
			body := append(make([]byte, 0, 64), "user "...)
			ctx.SetBody(append(body, path[len(usersPrefix):]...))
		case ctx.IsPost() && string(path) == "/echo":
			if ct := ctx.Request.Header.ContentType(); len(ct) > 0 {
				ctx.SetContentTypeBytes(ct)
			} else {
				ctx.SetContentType("application/octet-stream")
			}
			ctx.SetBody(ctx.PostBody())
		default:
			ctx.Error("404 page not found", fasthttp.StatusNotFound)
		}
	}

	srv := &fasthttp.Server{Handler: handler, Name: "fasthttp"}
	log.Printf("fasthttp listening on %s", *addr)
	log.Fatal(srv.ListenAndServe(*addr))
}
