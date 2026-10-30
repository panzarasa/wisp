// Command fiber is a reference for the HTTP benchmarks: gofiber/fiber v3,
// with its default settings, serving the same three routes as cmd/server
// with the same responses.
package main

import (
	"flag"
	"log"

	"github.com/gofiber/fiber/v3"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	flag.Int("loops", 0, "ignored: fiber has no event loops (GOMAXPROCS follows the CPUs the process may use)")
	flag.Parse()

	app := fiber.New()

	app.Get("/", func(c fiber.Ctx) error {
		return c.SendString("Hello, World!")
	})

	app.Get("/users/:id", func(c fiber.Ctx) error {
		c.Set(fiber.HeaderContentType, fiber.MIMETextPlainCharsetUTF8)
		body := append(make([]byte, 0, 64), "user "...)
		return c.Send(append(body, c.Params("id")...))
	})

	app.Post("/echo", func(c fiber.Ctx) error {
		contentType := "application/octet-stream"
		if v := c.Get(fiber.HeaderContentType); v != "" {
			contentType = v
		}
		c.Set(fiber.HeaderContentType, contentType)
		return c.Send(c.Body())
	})

	log.Printf("fiber listening on %s", *addr)
	log.Fatal(app.Listen(*addr, fiber.ListenConfig{DisableStartupMessage: true}))
}
