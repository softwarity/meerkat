package routing

import (
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"regexp"
)

// RequestFilter mutates the outgoing (proxied) request.
type RequestFilter func(*httputil.ProxyRequest)

// ResponseFilter mutates the upstream response before it reaches the client.
type ResponseFilter func(*http.Response) error

// CompiledFilters is the executable form of a route's filter list. When
// Terminal is set the route never proxies (e.g. redirect).
type CompiledFilters struct {
	Request  []RequestFilter
	Response []ResponseFilter
	Terminal http.Handler
	// IgnoredFilters counts the INCOMING filters dropped because a terminal
	// answers the route and nothing is proxied (see CompileFilters).
	IgnoredFilters int
	// TerminalNeedsIdentity says the terminal answers FROM the caller, so the
	// engine must resolve the session and carry it in (routing.WithIdentity).
	// Declared rather than assumed: resolving a session costs a read, and
	// redirect and maintenance have no use for one.
	TerminalNeedsIdentity bool
}

type filterPhase string

const (
	phaseRequest  filterPhase = "request"
	phaseResponse filterPhase = "response"
	phaseTerminal filterPhase = "terminal"
)

type filterDef struct {
	Type   string
	Doc    string
	Phase  filterPhase
	Params []Param

	compileRequest  func(a decoded) (RequestFilter, error)
	compileResponse func(a decoded) (ResponseFilter, error)
	compileTerminal func(a decoded) (http.Handler, error)
	// needsIdentity: the terminal reads the caller (see CompiledFilters).
	needsIdentity bool
}

// CompileFilters turns specs into executable chains, applied in declared
// order within each phase.
func CompileFilters(specs []Spec) (CompiledFilters, error) {
	var out CompiledFilters
	terminalType := ""
	for _, s := range specs {
		def, ok := filterRegistry[s.Type]
		if !ok {
			return out, fmt.Errorf("unknown filter type %q (available: %s)", s.Type, knownFilters())
		}
		args, err := decodeArgs("filter "+s.Type, def.Params, s.Args)
		if err != nil {
			return out, err
		}
		switch def.Phase {
		case phaseRequest:
			f, err := def.compileRequest(args)
			if err != nil {
				return out, err
			}
			out.Request = append(out.Request, f)
		case phaseResponse:
			f, err := def.compileResponse(args)
			if err != nil {
				return out, err
			}
			out.Response = append(out.Response, f)
		case phaseTerminal:
			if out.Terminal != nil {
				return out, fmt.Errorf("filter %s: a route can have only one terminal filter", s.Type)
			}
			h, err := def.compileTerminal(args)
			if err != nil {
				return out, err
			}
			out.Terminal = h
			out.TerminalNeedsIdentity = def.needsIdentity
			terminalType = s.Type
		}
	}
	// A terminal answers the route itself. INCOMING filters then have nothing
	// to modify — the request is never proxied — so they are dropped. OUTGOING
	// ones still apply: the answer is a response like any other, and putting a
	// CORS or a Cache-Control header on it is exactly as legitimate as on a
	// proxied one.
	//
	// Both used to be an error, which meant an existing route could not be
	// switched to an answering mode without first hunting down its modifiers in
	// two other sections — and the refusal named "redirect" whatever the
	// terminal actually was.
	if out.Terminal != nil && len(out.Request) > 0 {
		out.IgnoredFilters = len(out.Request)
		out.Request = nil
		slog.Warn("incoming filters ignored: this route answers by itself, nothing is proxied",
			"terminal", terminalType, "ignored", out.IgnoredFilters)
	}
	return out, nil
}

// LiteralArgs lists the arguments of a filter that must reach the brick
// untouched (see Param.Literal). Unknown filter: nothing to protect.
func LiteralArgs(filterType string) []string {
	def, ok := filterRegistry[filterType]
	if !ok {
		return nil
	}
	var out []string
	for _, p := range def.Params {
		if p.Literal {
			out = append(out, p.Name)
		}
	}
	return out
}

var filterRegistry = map[string]filterDef{}

func registerFilter(def filterDef) { filterRegistry[def.Type] = def }

func knownFilters() string {
	names := make([]string, 0, len(filterRegistry))
	for n := range filterRegistry {
		names = append(names, n)
	}
	return joinSorted(names)
}

func init() {
	// ---- request: path -----------------------------------------------------

	registerFilter(filterDef{
		Type: "strip-prefix", Phase: phaseRequest,
		Doc: "Removes the first N segments of the path before proxying.",
		Params: []Param{
			{Name: "parts", Kind: KindInt, Default: 1, Doc: "number of leading segments to remove"},
		},
		compileRequest: func(a decoded) (RequestFilter, error) {
			n := a.num("parts")
			if n < 1 {
				return nil, fmt.Errorf("strip-prefix: parts must be >= 1")
			}
			return func(pr *httputil.ProxyRequest) {
				pr.Out.URL.Path = StripSegments(pr.Out.URL.Path, n)
				pr.Out.URL.RawPath = ""
			}, nil
		},
	})

	registerFilter(filterDef{
		Type: "prefix-path", Phase: phaseRequest,
		Doc: "Prepends a prefix to the path before proxying.",
		Params: []Param{
			{Name: "prefix", Kind: KindString, Required: true},
		},
		compileRequest: func(a decoded) (RequestFilter, error) {
			prefix := a.str("prefix")
			return func(pr *httputil.ProxyRequest) {
				pr.Out.URL.Path = prefix + pr.Out.URL.Path
				pr.Out.URL.RawPath = ""
			}, nil
		},
	})

	registerFilter(filterDef{
		Type: "rewrite-path", Phase: phaseRequest,
		Doc: "Rewrites the path with a regexp replacement (capture groups as $1, $2…).",
		Params: []Param{
			{Name: "pattern", Kind: KindString, Required: true},
			{Name: "replacement", Kind: KindString, Required: true},
		},
		compileRequest: func(a decoded) (RequestFilter, error) {
			re, err := regexp.Compile(a.str("pattern"))
			if err != nil {
				return nil, fmt.Errorf("rewrite-path: bad pattern: %w", err)
			}
			repl := a.str("replacement")
			return func(pr *httputil.ProxyRequest) {
				pr.Out.URL.Path = re.ReplaceAllString(pr.Out.URL.Path, repl)
				pr.Out.URL.RawPath = ""
			}, nil
		},
	})

	// ---- request: headers & query ------------------------------------------

	registerFilter(filterDef{
		Type: "set-request-header", Phase: phaseRequest,
		Doc: "Sets a request header (replacing any client value).",
		Params: []Param{
			{Name: "name", Kind: KindString, Required: true},
			{Name: "value", Kind: KindString, Required: true},
		},
		compileRequest: func(a decoded) (RequestFilter, error) {
			name, value := a.str("name"), a.str("value")
			return func(pr *httputil.ProxyRequest) { pr.Out.Header.Set(name, value) }, nil
		},
	})

	registerFilter(filterDef{
		Type: "add-request-header", Phase: phaseRequest,
		Doc: "Adds a request header value; ifNotPresent skips when the client already sent one.",
		Params: []Param{
			{Name: "name", Kind: KindString, Required: true},
			{Name: "value", Kind: KindString, Required: true},
			{Name: "ifNotPresent", Kind: KindBool, Default: false},
		},
		compileRequest: func(a decoded) (RequestFilter, error) {
			name, value, skip := a.str("name"), a.str("value"), a.boolean("ifNotPresent")
			return func(pr *httputil.ProxyRequest) {
				if skip && pr.Out.Header.Get(name) != "" {
					return
				}
				pr.Out.Header.Add(name, value)
			}, nil
		},
	})

	registerFilter(filterDef{
		Type: "remove-request-header", Phase: phaseRequest,
		Doc: "Removes a request header before proxying.",
		Params: []Param{
			{Name: "name", Kind: KindString, Required: true},
		},
		compileRequest: func(a decoded) (RequestFilter, error) {
			name := a.str("name")
			return func(pr *httputil.ProxyRequest) { pr.Out.Header.Del(name) }, nil
		},
	})

	registerFilter(filterDef{
		Type: "set-query-param", Phase: phaseRequest,
		Doc: "Sets a query parameter on the proxied request.",
		Params: []Param{
			{Name: "name", Kind: KindString, Required: true},
			{Name: "value", Kind: KindString, Required: true},
		},
		compileRequest: func(a decoded) (RequestFilter, error) {
			name, value := a.str("name"), a.str("value")
			return func(pr *httputil.ProxyRequest) {
				q := pr.Out.URL.Query()
				q.Set(name, value)
				pr.Out.URL.RawQuery = q.Encode()
			}, nil
		},
	})

	registerFilter(filterDef{
		Type: "remove-query-param", Phase: phaseRequest,
		Doc: "Removes a query parameter from the proxied request.",
		Params: []Param{
			{Name: "name", Kind: KindString, Required: true},
		},
		compileRequest: func(a decoded) (RequestFilter, error) {
			name := a.str("name")
			return func(pr *httputil.ProxyRequest) {
				q := pr.Out.URL.Query()
				q.Del(name)
				pr.Out.URL.RawQuery = q.Encode()
			}, nil
		},
	})

	// ---- response ----------------------------------------------------------

	registerFilter(filterDef{
		Type: "set-response-header", Phase: phaseResponse,
		Doc: "Sets a response header (replacing any upstream value).",
		Params: []Param{
			{Name: "name", Kind: KindString, Required: true},
			{Name: "value", Kind: KindString, Required: true},
		},
		compileResponse: func(a decoded) (ResponseFilter, error) {
			name, value := a.str("name"), a.str("value")
			return func(res *http.Response) error { res.Header.Set(name, value); return nil }, nil
		},
	})

	registerFilter(filterDef{
		Type: "add-response-header", Phase: phaseResponse,
		Doc: "Adds a response header value.",
		Params: []Param{
			{Name: "name", Kind: KindString, Required: true},
			{Name: "value", Kind: KindString, Required: true},
		},
		compileResponse: func(a decoded) (ResponseFilter, error) {
			name, value := a.str("name"), a.str("value")
			return func(res *http.Response) error { res.Header.Add(name, value); return nil }, nil
		},
	})

	registerFilter(filterDef{
		Type: "remove-response-header", Phase: phaseResponse,
		Doc: "Removes a response header before it reaches the client.",
		Params: []Param{
			{Name: "name", Kind: KindString, Required: true},
		},
		compileResponse: func(a decoded) (ResponseFilter, error) {
			name := a.str("name")
			return func(res *http.Response) error { res.Header.Del(name); return nil }, nil
		},
	})

	registerFilter(filterDef{
		Type: "set-status", Phase: phaseResponse,
		Doc: "Overrides the upstream response status code.",
		Params: []Param{
			{Name: "status", Kind: KindInt, Required: true},
		},
		compileResponse: func(a decoded) (ResponseFilter, error) {
			status := a.num("status")
			if status < 100 || status > 599 {
				return nil, fmt.Errorf("set-status: %d is not a valid HTTP status", status)
			}
			return func(res *http.Response) error {
				res.StatusCode = status
				res.Status = http.StatusText(status)
				return nil
			}, nil
		},
	})

	// NOTE: the old generic "inject-head" filter is gone — page injections are
	// a UI-route affair (Injections section: custom CSS/JS, user button, page
	// stamps), all riding filters.InjectAfterHead internally.

	// ---- terminal ----------------------------------------------------------

	registerFilter(filterDef{
		Type: "maintenance", Phase: phaseTerminal,
		Doc: "Answers 503 with a gateway maintenance page instead of proxying.",
		Params: []Param{
			{Name: "message", Kind: KindString, Doc: "optional text shown on the page"},
		},
		compileTerminal: func(a decoded) (http.Handler, error) {
			page := maintenancePage(a.str("message"))
			return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Header().Set("Cache-Control", "no-store")
				w.Header().Set("Retry-After", "300")
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write(page)
			}), nil
		},
	})

	registerFilter(filterDef{
		Type: "redirect", Phase: phaseTerminal,
		Doc: "Answers with a redirect instead of proxying.",
		Params: []Param{
			{Name: "location", Kind: KindString, Required: true},
			{Name: "status", Kind: KindInt, Default: 302},
		},
		compileTerminal: func(a decoded) (http.Handler, error) {
			status := a.num("status")
			if status < 300 || status > 399 {
				return nil, fmt.Errorf("redirect: status must be 3xx, got %d", status)
			}
			location := a.str("location")
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, location, status)
			}), nil
		},
	})
}

// maintenancePage renders the built-in "under maintenance" answer: a sober
// dark page, self-contained (the gateway must run offline). The message is
// the admin's own text, escaped.
func maintenancePage(message string) []byte {
	extra := ""
	if message != "" {
		extra = `<p class="msg">` + html.EscapeString(message) + `</p>`
	}
	return []byte(`<!doctype html><html><head><meta charset="utf-8"><title>Maintenance</title>
<meta name="viewport" content="width=device-width, initial-scale=1"><style>
body { margin:0; min-height:100vh; display:grid; place-items:center; background:#1b2f40; color:#e6edf3; font-family:system-ui,sans-serif; }
main { text-align:center; padding:24px; }
h1 { font-size:1.3rem; letter-spacing:.1em; text-transform:uppercase; }
.msg { color:#9fb3c8; max-width:52ch; }
.dot { width:10px; height:10px; margin:20px auto 0; border-radius:50%; background:#25c2e0; box-shadow:0 0 12px #25c2e0; }
</style></head><body><main><h1>Under maintenance</h1>` + extra + `<div class="dot"></div></main></body></html>`)
}
