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
// "/users" and "/users/" are different paths.
//
// Routes must be registered before the server starts: lookups take no lock.
type Router struct {
	methods map[string]*methodRoutes

	// NotFound handles requests that match no route. The default answers 404,
	// or 405 with an Allow header if the path exists for other methods.
	NotFound Handler
}

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
	return &Router{methods: make(map[string]*methodRoutes)}
}

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

// Serve dispatches ctx to the matching handler. It is the Handler to give to
// a Server.
func (r *Router) Serve(c *Ctx) {
	h := r.lookup(c.Method, c.Path, c)
	if h == nil && string(c.Method) == "HEAD" {
		if h = r.lookup([]byte("GET"), c.Path, c); h != nil {
			c.head = true
		}
	}
	if h == nil {
		h = r.NotFound
		if h == nil {
			h = r.notFound
		}
	}
	h(c)
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
