// Package openapi reads an OpenAPI / Swagger specification and projects it down
// to the minimal shape Meerkat needs: the list of operations (method + path)
// that endpoint-level security (RBAC-07) binds to, and the served swagger-ui
// hangs off. Swagger 2.0 and OpenAPI 3.0/3.1 are both understood through
// libopenapi; callers see one version-agnostic Operation slice and never touch
// OpenAPI's complexity (schemas, $refs, parameters are deliberately dropped).
package openapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/pb33f/libopenapi"
	"github.com/pb33f/libopenapi/orderedmap"
)

// maxSpecBytes caps a fetched spec: enough for large real-world documents,
// small enough that a hostile or broken upstream cannot exhaust memory.
const maxSpecBytes = 12 << 20 // 12 MiB

// Operation is one method+path pair exposed by a spec, reduced to what the
// console shows and what a per-endpoint policy binds to.
type Operation struct {
	Method      string   `json:"method"` // upper-case HTTP verb
	Path        string   `json:"path"`   // spec path, e.g. /users/{id}
	OperationID string   `json:"operationId,omitempty"`
	Summary     string   `json:"summary,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// Spec is the parsed projection of an OpenAPI / Swagger document: API metadata
// plus the flat, sorted list of operations.
type Spec struct {
	Title      string      `json:"title,omitempty"`
	Version    string      `json:"version,omitempty"` // the API version (info.version)
	Format     string      `json:"format"`            // spec version, e.g. "2.0", "3.0.3", "3.1.0"
	Operations []Operation `json:"operations"`
}

// Parse reads a raw spec (JSON or YAML) and returns its operation projection.
// The spec version is auto-detected: "2.x" builds the Swagger model, "3.x" the
// OpenAPI one.
func Parse(data []byte) (*Spec, error) {
	doc, err := libopenapi.NewDocument(data)
	if err != nil {
		return nil, fmt.Errorf("openapi: not a readable spec: %w", err)
	}
	v := strings.TrimSpace(doc.GetVersion())
	switch {
	case strings.HasPrefix(v, "2"):
		return parseV2(doc)
	case strings.HasPrefix(v, "3"):
		return parseV3(doc)
	default:
		return nil, fmt.Errorf("openapi: unsupported spec version %q (want swagger 2.x or openapi 3.x)", v)
	}
}

func parseV2(doc libopenapi.Document) (*Spec, error) {
	m, err := doc.BuildV2Model()
	if err != nil {
		return nil, fmt.Errorf("openapi: build swagger 2.0 model: %w", err)
	}
	sw := &m.Model
	out := &Spec{Format: orDefault(sw.Swagger, "2.0")}
	if sw.Info != nil {
		out.Title, out.Version = sw.Info.Title, sw.Info.Version
	}
	if sw.Paths != nil {
		for pp := orderedmap.First(sw.Paths.PathItems); pp != nil; pp = pp.Next() {
			path := pp.Key()
			for op := orderedmap.First(pp.Value().GetOperations()); op != nil; op = op.Next() {
				o := op.Value()
				out.Operations = append(out.Operations, Operation{
					Method: strings.ToUpper(op.Key()), Path: path,
					OperationID: o.OperationId, Summary: o.Summary, Tags: o.Tags,
				})
			}
		}
	}
	sortOps(out.Operations)
	return out, nil
}

func parseV3(doc libopenapi.Document) (*Spec, error) {
	m, err := doc.BuildV3Model()
	if err != nil {
		return nil, fmt.Errorf("openapi: build openapi 3.x model: %w", err)
	}
	d := &m.Model
	out := &Spec{Format: orDefault(d.Version, "3.0")}
	if d.Info != nil {
		out.Title, out.Version = d.Info.Title, d.Info.Version
	}
	if d.Paths != nil {
		for pp := orderedmap.First(d.Paths.PathItems); pp != nil; pp = pp.Next() {
			path := pp.Key()
			for op := orderedmap.First(pp.Value().GetOperations()); op != nil; op = op.Next() {
				o := op.Value()
				out.Operations = append(out.Operations, Operation{
					Method: strings.ToUpper(op.Key()), Path: path,
					OperationID: o.OperationId, Summary: o.Summary, Tags: o.Tags,
				})
			}
		}
	}
	sortOps(out.Operations)
	return out, nil
}

// Fetch retrieves a spec over HTTP server-side and parses it. The caller
// supplies the client so timeouts and transport stay under the gateway's
// control. The raw bytes are returned alongside the projection: the served
// swagger-ui needs them (after Rewrite), the console only needs the Spec.
func Fetch(ctx context.Context, client *http.Client, url string) (*Spec, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("openapi: build request for %q: %w", url, err)
	}
	req.Header.Set("Accept", "application/json, application/yaml;q=0.9, text/yaml;q=0.9, */*;q=0.1")
	res, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("openapi: fetch %q: %w", url, err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("openapi: fetch %q: upstream returned %s", url, res.Status)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxSpecBytes))
	if err != nil {
		return nil, nil, fmt.Errorf("openapi: read %q: %w", url, err)
	}
	spec, err := Parse(body)
	if err != nil {
		return nil, nil, err
	}
	return spec, body, nil
}

// Rewrite adjusts a raw spec so a swagger-ui served BEHIND the gateway calls
// operations through the exposed base (UIF-07). A relative base keeps the
// current origin: Swagger 2.0 gets its basePath set (host and schemes dropped);
// OpenAPI 3.x gets a single relative server. An absolute base
// (scheme://host[/path]) points at ANOTHER origin — the API-docs page serves
// from the admin plane while the routes answer on the data plane — so 2.0 gets
// it decomposed into host/schemes/basePath and 3.x carries it verbatim. The
// spec is treated as JSON; a YAML-only spec is returned unchanged (swagger-ui
// still loads it, only gateway targeting is lost) with a non-nil error the
// caller may log.
func Rewrite(raw []byte, exposedBase string) ([]byte, error) {
	if exposedBase == "" {
		exposedBase = "/"
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return raw, fmt.Errorf("openapi: rewrite expects JSON: %w", err)
	}
	if _, isV2 := doc["swagger"]; isV2 {
		// The spec's own base path survives: the route forwards paths, so the
		// public path is <route prefix> + <spec base> (httpbin: "/", petstore:
		// "/api/v3").
		ownBase, _ := doc["basePath"].(string)
		delete(doc, "host")
		delete(doc, "schemes")
		if u, err := url.Parse(exposedBase); err == nil && u.Scheme != "" && u.Host != "" {
			doc["host"] = u.Host
			doc["schemes"] = []any{u.Scheme}
			doc["basePath"] = joinBasePaths(u.Path, ownBase)
		} else {
			doc["basePath"] = joinBasePaths(exposedBase, ownBase)
		}
	} else {
		// Same idea for 3.x: keep the PATH of the spec's first server (its
		// url is often relative, e.g. "/api/v3") under the exposed base.
		var ownPath string
		if servers, _ := doc["servers"].([]any); len(servers) > 0 {
			if first, _ := servers[0].(map[string]any); first != nil {
				if s, _ := first["url"].(string); s != "" {
					if u, err := url.Parse(s); err == nil {
						ownPath = u.Path
					}
				}
			}
		}
		base := strings.TrimSuffix(exposedBase, "/")
		if p := strings.Trim(ownPath, "/"); p != "" {
			base += "/" + p
		}
		if base == "" {
			base = "/"
		}
		doc["servers"] = []any{map[string]any{"url": base}}
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return raw, fmt.Errorf("openapi: rewrite marshal: %w", err)
	}
	return out, nil
}

// InjectSimulation declares the gateway's identity-simulation headers on a
// spec served by the API-docs page: swagger-ui's Authorize can then input a
// user and roles (2.0 gets securityDefinitions, 3.x components.securitySchemes)
// and every operation shows the padlock — the appended global requirement is
// OR-ed with whatever the spec already demands. Serve-time only, the stored
// spec is untouched. A YAML spec is returned unchanged with a non-nil error.
func InjectSimulation(raw []byte) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return raw, fmt.Errorf("openapi: inject expects JSON: %w", err)
	}
	schemes := map[string]any{
		"MeerkatSimulateUser": map[string]any{
			"type": "apiKey", "in": "header", "name": "X-Meerkat-Simulate-User",
			"description": "Try the route AS this username — no account needed. Honored only for signed-in gateway testers (root, infra-admin, dev, tester).",
		},
		"MeerkatSimulateRoles": map[string]any{
			"type": "apiKey", "in": "header", "name": "X-Meerkat-Simulate-Roles",
			"description": "Comma-separated roles of the simulated identity (e.g. auditor,sales).",
		},
	}
	if _, isV2 := doc["swagger"]; isV2 {
		defs, _ := doc["securityDefinitions"].(map[string]any)
		if defs == nil {
			defs = map[string]any{}
		}
		for k, v := range schemes {
			defs[k] = v
		}
		doc["securityDefinitions"] = defs
	} else {
		comps, _ := doc["components"].(map[string]any)
		if comps == nil {
			comps = map[string]any{}
		}
		ss, _ := comps["securitySchemes"].(map[string]any)
		if ss == nil {
			ss = map[string]any{}
		}
		for k, v := range schemes {
			ss[k] = v
		}
		comps["securitySchemes"] = ss
		doc["components"] = comps
	}
	sec, _ := doc["security"].([]any)
	doc["security"] = append(sec, map[string]any{"MeerkatSimulateUser": []any{}, "MeerkatSimulateRoles": []any{}})
	out, err := json.Marshal(doc)
	if err != nil {
		return raw, fmt.Errorf("openapi: inject marshal: %w", err)
	}
	return out, nil
}

// joinBasePaths joins the route's exposed path and the spec's own base path
// into one clean base ("" and "/" collapse; the result is never empty).
func joinBasePaths(exposed, own string) string {
	e := strings.TrimSuffix(exposed, "/")
	if o := strings.Trim(own, "/"); o != "" {
		e += "/" + o
	}
	if e == "" {
		return "/"
	}
	return e
}

// methodRank orders operations by the conventional REST verb sequence for a
// stable, readable listing.
func methodRank(m string) int {
	switch m {
	case "GET":
		return 0
	case "POST":
		return 1
	case "PUT":
		return 2
	case "PATCH":
		return 3
	case "DELETE":
		return 4
	case "HEAD":
		return 5
	case "OPTIONS":
		return 6
	default:
		return 7
	}
}

// sortOps gives a deterministic order: by path, then by verb rank. The console
// regroups by tag on top; tests rely on the determinism.
func sortOps(ops []Operation) {
	sort.SliceStable(ops, func(i, j int) bool {
		if ops[i].Path != ops[j].Path {
			return ops[i].Path < ops[j].Path
		}
		return methodRank(ops[i].Method) < methodRank(ops[j].Method)
	})
}

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}
