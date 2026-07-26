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
// operations through the exposed base path (UIF-07). Swagger 2.0 gets its
// basePath set (host and schemes dropped so the browser uses the current
// origin); OpenAPI 3.x gets a single relative server. The spec is treated as
// JSON; a YAML-only spec is returned unchanged (swagger-ui still loads it,
// only same-origin resolution is lost) with a non-nil error the caller may log.
func Rewrite(raw []byte, exposedBase string) ([]byte, error) {
	if exposedBase == "" {
		exposedBase = "/"
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return raw, fmt.Errorf("openapi: rewrite expects JSON: %w", err)
	}
	if _, isV2 := doc["swagger"]; isV2 {
		delete(doc, "host")
		delete(doc, "schemes")
		doc["basePath"] = exposedBase
	} else {
		doc["servers"] = []any{map[string]any{"url": exposedBase}}
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return raw, fmt.Errorf("openapi: rewrite marshal: %w", err)
	}
	return out, nil
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
