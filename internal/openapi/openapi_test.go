package openapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// hasOp reports whether the projection contains a given method+path.
func hasOp(ops []Operation, method, path string) *Operation {
	for i := range ops {
		if ops[i].Method == method && ops[i].Path == path {
			return &ops[i]
		}
	}
	return nil
}

// The real httpbin spec is Swagger 2.0: it exercises the v2 model path and the
// templated segments ({anything}) the endpoint matcher relies on.
func TestParseSwagger2Httpbin(t *testing.T) {
	raw, err := os.ReadFile("testdata/httpbin-2.0.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	spec, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if spec.Format != "2.0" {
		t.Errorf("format = %q, want 2.0", spec.Format)
	}
	if spec.Title == "" {
		t.Error("title should be populated from info.title")
	}
	if len(spec.Operations) < 30 {
		t.Fatalf("expected many operations, got %d", len(spec.Operations))
	}
	for _, want := range []struct{ m, p string }{
		{"GET", "/get"}, {"POST", "/post"}, {"DELETE", "/delete"}, {"PATCH", "/patch"},
		{"GET", "/anything/{anything}"},
	} {
		if hasOp(spec.Operations, want.m, want.p) == nil {
			t.Errorf("missing operation %s %s", want.m, want.p)
		}
	}
	// Deterministic order: sorted by path then verb rank.
	for i := 1; i < len(spec.Operations); i++ {
		a, b := spec.Operations[i-1], spec.Operations[i]
		if a.Path > b.Path {
			t.Fatalf("operations not sorted by path at %d: %q then %q", i, a.Path, b.Path)
		}
	}
}

const openapi30 = `{
  "openapi": "3.0.3",
  "info": {"title": "Orders API", "version": "1.2.0"},
  "servers": [{"url": "https://api.example.com/v1"}],
  "paths": {
    "/orders": {
      "get": {"operationId": "listOrders", "summary": "List orders", "tags": ["orders"]},
      "post": {"operationId": "createOrder", "tags": ["orders"]}
    },
    "/orders/{id}": {
      "get": {"operationId": "getOrder", "tags": ["orders"]},
      "delete": {"operationId": "deleteOrder", "tags": ["orders", "admin"]}
    }
  }
}`

func TestParseOpenAPI3(t *testing.T) {
	spec, err := Parse([]byte(openapi30))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if spec.Format != "3.0.3" {
		t.Errorf("format = %q, want 3.0.3", spec.Format)
	}
	if spec.Title != "Orders API" || spec.Version != "1.2.0" {
		t.Errorf("metadata = %q %q", spec.Title, spec.Version)
	}
	if len(spec.Operations) != 4 {
		t.Fatalf("want 4 operations, got %d", len(spec.Operations))
	}
	del := hasOp(spec.Operations, "DELETE", "/orders/{id}")
	if del == nil {
		t.Fatal("missing DELETE /orders/{id}")
	}
	if del.OperationID != "deleteOrder" || len(del.Tags) != 2 {
		t.Errorf("operation metadata not carried: %+v", del)
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	if _, err := Parse([]byte(`{"not":"a spec"}`)); err == nil {
		t.Error("expected an error for a spec with no version")
	}
}

func TestRewriteSwagger2(t *testing.T) {
	in := []byte(`{"swagger":"2.0","host":"httpbin.org","basePath":"/","schemes":["https"],"paths":{}}`)
	out, err := Rewrite(in, "/demo")
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["basePath"] != "/demo" {
		t.Errorf("basePath = %v, want /demo", doc["basePath"])
	}
	if _, ok := doc["host"]; ok {
		t.Error("host must be dropped so the browser uses the gateway origin")
	}
	if _, ok := doc["schemes"]; ok {
		t.Error("schemes must be dropped")
	}
}

// An absolute base crosses origins (admin plane → data plane): 2.0 gets it
// decomposed, so a spec shipping its own host (httpbin does) is fully retargeted.
func TestRewriteSwagger2AbsoluteBase(t *testing.T) {
	in := []byte(`{"swagger":"2.0","host":"httpbin.org","basePath":"/","schemes":["https"],"paths":{}}`)
	out, err := Rewrite(in, "http://localhost:8082/demo")
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["host"] != "localhost:8082" {
		t.Errorf("host = %v, want localhost:8082", doc["host"])
	}
	if doc["basePath"] != "/demo" {
		t.Errorf("basePath = %v, want /demo", doc["basePath"])
	}
	schemes, _ := doc["schemes"].([]any)
	if len(schemes) != 1 || schemes[0] != "http" {
		t.Errorf("schemes = %v, want [http]", doc["schemes"])
	}
}

func TestRewriteOpenAPI3AbsoluteBase(t *testing.T) {
	out, err := Rewrite([]byte(openapi30), "http://localhost:8082")
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	servers, ok := doc["servers"].([]any)
	if !ok || len(servers) != 1 || servers[0].(map[string]any)["url"] != "http://localhost:8082/v1" {
		t.Fatalf("servers = %v, want the absolute base + the spec's own /v1", doc["servers"])
	}
}

// InjectSimulation declares the simulate headers so Authorize can input them,
// on both spec generations, without erasing what the spec already declares.
func TestInjectSimulation(t *testing.T) {
	v2 := []byte(`{"swagger":"2.0","securityDefinitions":{"own":{"type":"basic"}},"security":[{"own":[]}],"paths":{}}`)
	out, err := InjectSimulation(v2)
	if err != nil {
		t.Fatalf("inject v2: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	defs := doc["securityDefinitions"].(map[string]any)
	if _, ok := defs["MeerkatSimulateUser"]; !ok {
		t.Fatal("v2: simulate scheme missing")
	}
	if _, ok := defs["own"]; !ok {
		t.Fatal("v2: the spec's own scheme must survive")
	}
	if sec := doc["security"].([]any); len(sec) != 2 {
		t.Fatalf("v2: global security = %v, want the spec's own OR simulation", sec)
	}

	out, err = InjectSimulation([]byte(openapi30))
	if err != nil {
		t.Fatalf("inject v3: %v", err)
	}
	doc = map[string]any{}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	ss := doc["components"].(map[string]any)["securitySchemes"].(map[string]any)
	if _, ok := ss["MeerkatSimulateRoles"]; !ok {
		t.Fatal("v3: simulate scheme missing")
	}
}

func TestRewriteOpenAPI3(t *testing.T) {
	out, err := Rewrite([]byte(openapi30), "/demo")
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	servers, ok := doc["servers"].([]any)
	if !ok || len(servers) != 1 {
		t.Fatalf("servers = %v", doc["servers"])
	}
	// The spec's own path (/v1) survives under the exposed base: the route
	// forwards paths, so the public URL keeps carrying it.
	if servers[0].(map[string]any)["url"] != "/demo/v1" {
		t.Errorf("server url = %v, want /demo/v1", servers[0])
	}
}

func TestFetch(t *testing.T) {
	raw, err := os.ReadFile("testdata/httpbin-2.0.json")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	}))
	defer srv.Close()

	spec, body, err := Fetch(context.Background(), srv.Client(), srv.URL+"/spec.json")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(body) != len(raw) {
		t.Errorf("raw body length = %d, want %d", len(body), len(raw))
	}
	if hasOp(spec.Operations, "GET", "/get") == nil {
		t.Error("fetched spec missing GET /get")
	}

	// A non-200 upstream is a clear error, not a silent empty spec.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer bad.Close()
	if _, _, err := Fetch(context.Background(), bad.Client(), bad.URL); err == nil {
		t.Error("expected an error on a 404 spec fetch")
	}
}
