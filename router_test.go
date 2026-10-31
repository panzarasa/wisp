package wisp

import (
	"strings"
	"testing"

	"github.com/panzarasa/wisp/wildcat"
)

// route registers a handler that answers with name, so a test can tell which
// route was matched.
func route(r *Router, method, pattern, name string) {
	r.Handle(method, pattern, func(c *Ctx) { c.Text(200, name) })
}

func testRouter() *Router {
	r := NewRouter()
	route(r, "GET", "/", "root")
	route(r, "GET", "/users", "users")
	route(r, "GET", "/users/", "users-slash")
	route(r, "GET", "/users/:id", "user")
	route(r, "POST", "/users/:id", "user-post")
	route(r, "GET", "/users/me/settings", "my-settings")
	route(r, "GET", "/users/:id/posts/:post", "post")
	route(r, "GET", "/static/*file", "static")
	route(r, "GET", "/a/:x/c", "a-x-c")
	route(r, "GET", "/a/b/*rest", "a-b-rest")
	route(r, "DELETE", "/users/:id", "user-delete")
	return r
}

func TestRouterMatch(t *testing.T) {
	r := testRouter()

	tests := []struct {
		method, path string
		want         string // body of the matched route
		params       string // "key=value key=value"
	}{
		{"GET", "/", "root", ""},
		{"GET", "/users", "users", ""},
		{"GET", "/users/", "users-slash", ""},
		{"GET", "/users/42", "user", "id=42"},
		{"POST", "/users/42", "user-post", "id=42"},
		{"GET", "/users/42/posts/7", "post", "id=42 post=7"},
		{"GET", "/users/me/settings", "my-settings", ""},
		// "me" is a literal child of /users but leads nowhere on its own:
		// the lookup has to come back and take :id.
		{"GET", "/users/me", "user", "id=me"},
		{"GET", "/users/me/posts/7", "post", "id=me post=7"},
		{"GET", "/static/css/site.css", "static", "file=css/site.css"},
		{"GET", "/static/", "static", "file="},
		{"GET", "/a/b/c", "a-b-rest", "rest=c"},
		{"GET", "/a/z/c", "a-x-c", "x=z"},
		{"GET", "/a/b/c/d", "a-b-rest", "rest=c/d"},
		{"HEAD", "/users/42", "", "id=42"},
	}

	for _, tt := range tests {
		c := &Ctx{Method: []byte(tt.method), Path: []byte(tt.path)}
		r.Serve(c)

		status, body := splitResponse(t, c.out)
		if status != 200 {
			t.Errorf("%s %s: status %d, want 200", tt.method, tt.path, status)
			continue
		}
		if body != tt.want {
			t.Errorf("%s %s: matched %q, want %q", tt.method, tt.path, body, tt.want)
		}

		var params []string
		for i := 0; i < c.nparams; i++ {
			params = append(params, c.params[i].key+"="+string(c.params[i].value))
		}
		if got := strings.Join(params, " "); got != tt.params {
			t.Errorf("%s %s: params %q, want %q", tt.method, tt.path, got, tt.params)
		}
	}
}

func TestRouterNotFound(t *testing.T) {
	r := testRouter()

	tests := []struct {
		method, path string
		status       int
		allow        string
	}{
		{"GET", "/nope", 404, ""},
		{"GET", "/users//posts/7", 404, ""},
		{"GET", "/users/42/posts", 404, ""},
		{"GET", "/a/z/d", 404, ""},
		{"GET", "", 404, ""},
		{"GET", "*", 404, ""},
		{"PUT", "/users/42", 405, "DELETE, GET, POST"},
		{"POST", "/", 405, "GET"},
		{"BREW", "/nope", 404, ""},
	}

	for _, tt := range tests {
		c := &Ctx{Method: []byte(tt.method), Path: []byte(tt.path)}
		r.Serve(c)

		status, _ := splitResponse(t, c.out)
		if status != tt.status {
			t.Errorf("%s %q: status %d, want %d", tt.method, tt.path, status, tt.status)
		}
		if tt.allow != "" && !strings.Contains(string(c.out), "\r\nAllow: "+tt.allow+"\r\n") {
			t.Errorf("%s %q: want Allow: %s in\n%s", tt.method, tt.path, tt.allow, c.out)
		}
	}
}

func TestRouterCustomNotFound(t *testing.T) {
	r := NewRouter()
	r.NotFound = func(c *Ctx) { c.Text(404, "custom") }

	c := &Ctx{Method: []byte("GET"), Path: []byte("/x")}
	r.Serve(c)

	if status, body := splitResponse(t, c.out); status != 404 || body != "custom" {
		t.Errorf("got %d %q, want 404 custom", status, body)
	}
}

func TestRouterInvalidPatterns(t *testing.T) {
	h := func(c *Ctx) {}

	tests := []struct {
		name     string
		register func(r *Router)
	}{
		{"no leading slash", func(r *Router) { r.GET("users", h) }},
		{"nil handler", func(r *Router) { r.GET("/", nil) }},
		{"duplicate", func(r *Router) { r.GET("/a", h); r.GET("/a", h) }},
		{"duplicate param", func(r *Router) { r.GET("/a/:x", h); r.GET("/a/:x", h) }},
		{"param renamed", func(r *Router) { r.GET("/a/:x", h); r.GET("/a/:y/b", h) }},
		{"unnamed param", func(r *Router) { r.GET("/a/:", h) }},
		{"unnamed catch-all", func(r *Router) { r.GET("/a/*", h) }},
		{"catch-all not last", func(r *Router) { r.GET("/a/*rest/b", h) }},
		{"duplicate catch-all", func(r *Router) { r.GET("/a/*x", h); r.GET("/a/*y", h) }},
		{"too many params", func(r *Router) { r.GET(strings.Repeat("/:p", MaxParams+1), h) }},
	}

	for _, tt := range tests {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: Handle did not panic", tt.name)
				}
			}()
			tt.register(NewRouter())
		}()
	}
}

func TestRouterRedirectTrailingSlash(t *testing.T) {
	r := NewRouter()
	route(r, "GET", "/docs/", "docs")
	route(r, "GET", "/users/:id", "user")
	route(r, "POST", "/items", "items")
	route(r, "GET", "/static/*file", "static")
	route(r, "GET", "/exact", "exact")
	route(r, "GET", "/exact/", "exact-slash")

	tests := []struct {
		method, raw, query string
		status             int
		location           string
	}{
		{"GET", "/docs", "", 301, "/docs/"},
		{"HEAD", "/docs", "", 301, "/docs/"},
		{"GET", "/users/42/", "a=1&b", 301, "/users/42?a=1&b"},
		{"POST", "/items/", "", 308, "/items"},
		{"GET", "/static", "", 301, "/static/"},
		{"GET", "/caf%C3%A9/", "", 404, ""},
		{"GET", "/exact", "", 200, ""},
		{"GET", "/exact/", "", 200, ""},
		{"PUT", "/items/", "", 404, ""},
		{"GET", "//docs", "", 404, ""},
		{"GET", "/", "", 404, ""},
	}
	for _, tt := range tests {
		c := &Ctx{Method: []byte(tt.method), RawPath: []byte(tt.raw), Query: []byte(tt.query)}
		c.Path = c.RawPath
		if strings.Contains(tt.raw, "%") {
			c.Path, _ = unescapePath(nil, c.RawPath)
		}
		r.Serve(c)
		resp := string(c.out)
		status, _ := splitResponse(t, c.out)
		if status != tt.status || tt.location != "" && !strings.Contains(resp, "\r\nLocation: "+tt.location+"\r\n") {
			t.Errorf("%s %s?%s: got\n%s", tt.method, tt.raw, tt.query, resp)
		}
		if c.nparams != 0 && status != 200 {
			t.Errorf("%s %s: %d params left", tt.method, tt.raw, c.nparams)
		}
	}

	r.RedirectTrailingSlash = false
	c := &Ctx{Method: []byte("GET"), Path: []byte("/docs")}
	r.Serve(c)
	if status, _ := splitResponse(t, c.out); status != 404 {
		t.Errorf("redirect disabled: %d", status)
	}
}

func TestRouterOptionsStar(t *testing.T) {
	r := testRouter()
	c := &Ctx{Method: []byte("OPTIONS"), Path: []byte("*")}
	r.Serve(c)
	if status, _ := splitResponse(t, c.out); status != 204 || !strings.Contains(string(c.out), "\r\nAllow: DELETE, GET, HEAD, OPTIONS, POST\r\n") {
		t.Errorf("got\n%s", c.out)
	}
}

// tag is a middleware that records its name on the way in and out.
func tag(trace *[]string, name string) Middleware {
	return func(next Handler) Handler {
		return func(c *Ctx) {
			*trace = append(*trace, name)
			next(c)
			*trace = append(*trace, "/"+name)
		}
	}
}

func TestRouterMiddleware(t *testing.T) {
	var trace []string
	r := NewRouter()
	r.Use(tag(&trace, "a"), tag(&trace, "b"))
	route(r, "GET", "/", "root")

	api := r.Group("/api/", tag(&trace, "api"))
	api.GET("", func(c *Ctx) { trace = append(trace, "index"); c.Text(200, "api") })
	api.GET("/users/:id", func(c *Ctx) { trace = append(trace, "user"); c.Bytes(200, MIMETextPlain, c.Param("id")) })
	v2 := api.Group("/v2", tag(&trace, "v2"))
	api.Use(tag(&trace, "late")) // only for the routes registered from now on
	v2.GET("/x", func(c *Ctx) { trace = append(trace, "x"); c.Text(200, "x") })
	api.GET("/y", func(c *Ctx) { trace = append(trace, "y"); c.Text(200, "y") })

	auth := r.Group("/admin", func(next Handler) Handler {
		return func(c *Ctx) {
			if string(c.Header("Authorization")) == "" {
				c.Text(401, "no")
				return
			}
			next(c)
		}
	})
	auth.GET("/", func(c *Ctx) { c.Text(200, "admin") })

	tests := []struct {
		path, body, trace string
	}{
		{"/", "root", "a b /b /a"},
		{"/api", "api", "a b api index /api /b /a"},
		{"/api/users/7", "7", "a b api user /api /b /a"},
		{"/api/v2/x", "x", "a b api v2 x /v2 /api /b /a"},
		{"/api/y", "y", "a b api late y /late /api /b /a"},
		{"/nope", "Not Found", "a b /b /a"},
		{"/admin/", "no", "a b /b /a"},
	}
	for _, tt := range tests {
		trace = nil
		c := &Ctx{Method: []byte("GET"), Path: []byte(tt.path), req: &wildcat.HTTPParser{}}
		r.Serve(c)
		_, body := splitResponse(t, c.out)
		if body != tt.body || strings.Join(trace, " ") != tt.trace {
			t.Errorf("GET %s: %q, trace %q, want %q %q", tt.path, body, strings.Join(trace, " "), tt.body, tt.trace)
		}
	}

	for _, bad := range []func(){
		func() { r.Group("api") },
		func() { api.GET("x", func(*Ctx) {}) },
		func() { api.GET("/nil", nil) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Error("no panic")
				}
			}()
			bad()
		}()
	}
}
