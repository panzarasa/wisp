package wisp

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
)

// Router matches a request method and path to a Handler.
//
// Patterns are made of '/'-separated segments. A segment is either literal,
// ":name" (matches one non-empty segment) or "*name" (last segment only,
// matches the rest of the path, possibly empty):
//
//	/users/:id
//	/users/:id/posts/:post
//	/static/*file
//
// Literal segments win over ":name", which wins over "*name"; when the
// preferred branch does not lead to a route the next one is tried, so
// "/users/me/settings" and "/users/:id" can coexist. Matching is exact:
// "/users" and "/users/" are different paths, but see RedirectTrailingSlash.
//
// Middleware added with Use wraps every request; a Group registers routes
// under a common prefix, wrapped in middleware of its own.
//
// Routes and middleware must be registered before the server starts: lookups
// take no lock.
type Router struct {
	methods map[string]*methodRoutes
	mws     []Middleware
	chain   Handler // dispatch wrapped in mws; nil without middleware

	// NotFound handles requests that match no route. The default answers 404,
	// or 405 with an Allow header if the path exists for other methods.
	NotFound Handler

	// RedirectTrailingSlash redirects a request that matches no route to the
	// same path with the trailing slash added or removed, if that matches
	// one: 301 for GET and HEAD, 308 (which keeps the method and body) for
	// the others. NewRouter enables it.
	RedirectTrailingSlash bool
}

// Middleware wraps a handler: it may act before and after calling next, or
// answer itself and not call it.
//
//	func logger(next wisp.Handler) wisp.Handler {
//		return func(c *wisp.Ctx) {
//			start := time.Now()
//			next(c)
//			log.Printf("%s %s %v", c.Method, c.Path, time.Since(start))
//		}
//	}
type Middleware func(next Handler) Handler

type methodRoutes struct {
	// Patterns without parameters, by full path: the common case skips the tree.
	static map[string]Handler
	root   node
}

type node struct {
	literal  map[string]*node
	param    *node
	paramKey string
	catchAll Handler
	catchKey string
	handler  Handler
}

func NewRouter() *Router {
	return &Router{methods: make(map[string]*methodRoutes), RedirectTrailingSlash: true}
}

// Use adds middleware that wraps every request the Router serves, matched or
// not; the first one added runs first.
func (r *Router) Use(mws ...Middleware) {
	r.mws = append(r.mws, mws...)
	r.chain = wrap(r.dispatch, r.mws)
}

// wrap returns h wrapped in mws, the first one outermost.
func wrap(h Handler, mws []Middleware) Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

// Group returns a Group of routes under prefix ("/api"), wrapped in mws.
func (r *Router) Group(prefix string, mws ...Middleware) *Group {
	return newGroup(r, "", nil, prefix, mws)
}

// Group registers routes under a common path prefix, each wrapped in the
// group's middleware (after the Router's).
type Group struct {
	r      *Router
	prefix string
	mws    []Middleware
}

func newGroup(r *Router, base string, baseMws []Middleware, prefix string, mws []Middleware) *Group {
	if !strings.HasPrefix(prefix, "/") {
		panic(fmt.Sprintf("wisp: group prefix %q must begin with '/'", prefix))
	}
	return &Group{
		r:      r,
		prefix: base + strings.TrimRight(prefix, "/"),
		mws:    append(append([]Middleware(nil), baseMws...), mws...),
	}
}

// Group returns a group nested in g: its prefix follows g's, and its
// middleware runs after g's.
func (g *Group) Group(prefix string, mws ...Middleware) *Group {
	return newGroup(g.r, g.prefix, g.mws, prefix, mws)
}

// Use adds middleware to the routes registered on g from now on.
func (g *Group) Use(mws ...Middleware) {
	g.mws = append(g.mws, mws...)
}

// Handle registers h for method and the group's prefix followed by pattern;
// an empty pattern is the prefix itself.
func (g *Group) Handle(method, pattern string, h Handler) {
	if pattern != "" && !strings.HasPrefix(pattern, "/") {
		panic(fmt.Sprintf("wisp: pattern %q must begin with '/'", pattern))
	}
	full := g.prefix + pattern
	if full == "" {
		full = "/"
	}
	if h != nil {
		h = wrap(h, g.mws)
	}
	g.r.Handle(method, full, h)
}

func (g *Group) GET(pattern string, h Handler)    { g.Handle("GET", pattern, h) }
func (g *Group) POST(pattern string, h Handler)   { g.Handle("POST", pattern, h) }
func (g *Group) PUT(pattern string, h Handler)    { g.Handle("PUT", pattern, h) }
func (g *Group) PATCH(pattern string, h Handler)  { g.Handle("PATCH", pattern, h) }
func (g *Group) DELETE(pattern string, h Handler) { g.Handle("DELETE", pattern, h) }

func (r *Router) GET(pattern string, h Handler)    { r.Handle("GET", pattern, h) }
func (r *Router) POST(pattern string, h Handler)   { r.Handle("POST", pattern, h) }
func (r *Router) PUT(pattern string, h Handler)    { r.Handle("PUT", pattern, h) }
func (r *Router) PATCH(pattern string, h Handler)  { r.Handle("PATCH", pattern, h) }
func (r *Router) DELETE(pattern string, h Handler) { r.Handle("DELETE", pattern, h) }

// Handle registers h for method and pattern. It panics on an invalid or
// conflicting pattern, like http.ServeMux.
func (r *Router) Handle(method, pattern string, h Handler) {
	if method == "" || h == nil {
		panic("wisp: empty method or nil handler for " + pattern)
	}
	if !strings.HasPrefix(pattern, "/") {
		panic(fmt.Sprintf("wisp: pattern %q must begin with '/'", pattern))
	}

	mr := r.methods[method]
	if mr == nil {
		mr = &methodRoutes{static: make(map[string]Handler)}
		r.methods[method] = mr
	}

	segments := strings.Split(pattern[1:], "/")
	n := &mr.root
	nparams := 0
	for i, seg := range segments {
		last := i == len(segments)-1

		switch {
		case strings.HasPrefix(seg, "*"):
			key := seg[1:]
			if key == "" || !last {
				panic(fmt.Sprintf("wisp: %q: a '*name' segment must be named and be the last one", pattern))
			}
			if n.catchAll != nil {
				panic(fmt.Sprintf("wisp: %s %q conflicts with an existing route", method, pattern))
			}
			if nparams++; nparams > MaxParams {
				panic(fmt.Sprintf("wisp: %q has more than %d parameters", pattern, MaxParams))
			}
			n.catchAll, n.catchKey = h, key
			return

		case strings.HasPrefix(seg, ":"):
			key := seg[1:]
			if key == "" {
				panic(fmt.Sprintf("wisp: %q: a ':name' segment must be named", pattern))
			}
			if n.param == nil {
				n.param, n.paramKey = &node{}, key
			} else if n.paramKey != key {
				panic(fmt.Sprintf("wisp: %q names a parameter :%s where an existing route names it :%s", pattern, key, n.paramKey))
			}
			if nparams++; nparams > MaxParams {
				panic(fmt.Sprintf("wisp: %q has more than %d parameters", pattern, MaxParams))
			}
			n = n.param

		default:
			child := n.literal[seg]
			if child == nil {
				if n.literal == nil {
					n.literal = make(map[string]*node)
				}
				child = &node{}
				n.literal[seg] = child
			}
			n = child
		}
	}

	if n.handler != nil {
		panic(fmt.Sprintf("wisp: %s %q conflicts with an existing route", method, pattern))
	}
	n.handler = h
	if nparams == 0 {
		mr.static[pattern] = h
	}
}

// Serve dispatches ctx to the matching handler, through the middleware. It
// is the Handler to give to a Server.
func (r *Router) Serve(c *Ctx) {
	if r.chain != nil {
		r.chain(c)
		return
	}
	r.dispatch(c)
}

var methodGET = []byte("GET")

func (r *Router) dispatch(c *Ctx) {
	h := r.lookup(c.Method, c.Path, c)
	if h == nil && string(c.Method) == "HEAD" {
		if h = r.lookup(methodGET, c.Path, c); h != nil {
			c.head = true
		}
	}
	if h != nil {
		h(c)
		return
	}
	if string(c.Path) == "*" && string(c.Method) == "OPTIONS" {
		r.optionsAll(c)
		return
	}
	if r.RedirectTrailingSlash && r.redirectSlash(c) {
		return
	}
	if h = r.NotFound; h == nil {
		h = r.notFound
	}
	h(c)
}

// redirectSlash redirects c if its path with the trailing slash toggled
// matches a route.
func (r *Router) redirectSlash(c *Ctx) bool {
	p := c.Path
	// "//host" in Location would be another site.
	if len(p) < 2 || p[0] != '/' || p[1] == '/' {
		return false
	}
	var buf [256]byte
	var alt []byte
	if p[len(p)-1] == '/' {
		alt = p[:len(p)-1]
	} else {
		alt = append(append(buf[:0], p...), '/')
	}
	found := r.lookup(c.Method, alt, c) != nil ||
		string(c.Method) == "HEAD" && r.lookup(methodGET, alt, c) != nil
	c.nparams = 0
	if !found {
		return false
	}

	raw := c.RawPath
	if raw == nil {
		raw = c.Path
	}
	loc := make([]byte, 0, len(raw)+1+len(c.Query)+1)
	if raw[len(raw)-1] == '/' {
		loc = append(loc, raw[:len(raw)-1]...)
	} else {
		loc = append(append(loc, raw...), '/')
	}
	if len(c.Query) > 0 {
		loc = append(append(loc, '?'), c.Query...)
	}
	status := 308
	if m := string(c.Method); m == "GET" || m == "HEAD" {
		status = 301
	}
	c.SetHeader("Location", string(loc))
	c.Text(status, statusText(status))
	return true
}

// optionsAll answers "OPTIONS *" with the methods of the server.
func (r *Router) optionsAll(c *Ctx) {
	allow := []string{"OPTIONS"}
	for method := range r.methods {
		if method != "OPTIONS" {
			allow = append(allow, method)
		}
	}
	if r.methods["GET"] != nil && r.methods["HEAD"] == nil {
		allow = append(allow, "HEAD")
	}
	sort.Strings(allow)
	c.SetHeader("Allow", strings.Join(allow, ", "))
	c.Status(204)
}

func (r *Router) lookup(method, path []byte, c *Ctx) Handler {
	mr := r.methods[string(method)]
	if mr == nil {
		return nil
	}
	if h, ok := mr.static[string(path)]; ok {
		return h
	}
	if len(path) == 0 || path[0] != '/' {
		return nil
	}

	c.nparams = 0
	return mr.root.find(path[1:], c)
}

// find matches rest, the path below n without its leading '/'.
func (n *node) find(rest []byte, c *Ctx) Handler {
	seg, tail := rest, []byte(nil)
	last := true
	if i := bytes.IndexByte(rest, '/'); i >= 0 {
		seg, tail, last = rest[:i], rest[i+1:], false
	}

	if child := n.literal[string(seg)]; child != nil {
		if last {
			if child.handler != nil {
				return child.handler
			}
		} else if h := child.find(tail, c); h != nil {
			return h
		}
	}

	if n.param != nil && len(seg) > 0 {
		mark := c.nparams
		c.params[c.nparams] = param{n.paramKey, seg}
		c.nparams++

		if last {
			if n.param.handler != nil {
				return n.param.handler
			}
		} else if h := n.param.find(tail, c); h != nil {
			return h
		}
		c.nparams = mark
	}

	if n.catchAll != nil {
		c.params[c.nparams] = param{n.catchKey, rest}
		c.nparams++
		return n.catchAll
	}

	return nil
}

func (r *Router) notFound(c *Ctx) {
	var allow []string
	for method := range r.methods {
		if r.lookup([]byte(method), c.Path, c) != nil {
			allow = append(allow, method)
		}
	}
	c.nparams = 0

	if len(allow) == 0 {
		c.Text(404, "Not Found")
		return
	}

	sort.Strings(allow)
	c.SetHeader("Allow", strings.Join(allow, ", "))
	c.Text(405, "Method Not Allowed")
}
