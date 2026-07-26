package filters

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

func htmlResponse(body string, header http.Header) *http.Response {
	h := http.Header{"Content-Type": []string{"text/html; charset=utf-8"}}
	for k, v := range header {
		h[k] = v
	}
	return &http.Response{
		Header:        h,
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}

func readBody(t *testing.T, res *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}

func TestInjectsAfterHeadTag(t *testing.T) {
	res := htmlResponse(`<html><head lang="en"><title>t</title></head></html>`, nil)
	if err := InjectAfterHead(`<script>x</script>`)(res); err != nil {
		t.Fatal(err)
	}
	got := readBody(t, res)
	want := `<html><head lang="en"><script>x</script><title>t</title></head></html>`
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if res.ContentLength != int64(len(want)) {
		t.Fatalf("ContentLength = %d, want %d", res.ContentLength, len(want))
	}
}

func TestPrependsWhenNoHead(t *testing.T) {
	res := htmlResponse(`<p>hi</p>`, nil)
	if err := InjectAfterHead(`<x/>`)(res); err != nil {
		t.Fatal(err)
	}
	if got := readBody(t, res); got != `<x/><p>hi</p>` {
		t.Fatalf("got %q", got)
	}
}

func TestSkipsNonHTML(t *testing.T) {
	res := &http.Response{
		Header: http.Header{"Content-Type": []string{"application/json"}},
		Body:   io.NopCloser(strings.NewReader(`{"a":1}`)),
	}
	if err := InjectAfterHead(`<x/>`)(res); err != nil {
		t.Fatal(err)
	}
	if got := readBody(t, res); got != `{"a":1}` {
		t.Fatalf("non-HTML body was modified: %q", got)
	}
}

func TestGzipRoundTrip(t *testing.T) {
	zipped, err := gzipBytes([]byte(`<html><head></head><body></body></html>`))
	if err != nil {
		t.Fatal(err)
	}
	res := &http.Response{
		Header: http.Header{
			"Content-Type":     []string{"text/html"},
			"Content-Encoding": []string{"gzip"},
		},
		Body:          io.NopCloser(bytes.NewReader(zipped)),
		ContentLength: int64(len(zipped)),
	}
	if err := InjectAfterHead(`<meta name="m">`)(res); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := gunzip(out)
	if err != nil {
		t.Fatalf("output is not valid gzip: %v", err)
	}
	if want := `<html><head><meta name="m"></head><body></body></html>`; string(plain) != want {
		t.Fatalf("got %q, want %q", plain, want)
	}
}

func TestRewriteHTMLFunc(t *testing.T) {
	// A false gate skips everything (body untouched, not buffered/mutated).
	res := htmlResponse(`<body>x</body>`, nil)
	skip := RewriteHTMLFunc(func(*http.Response) bool { return false },
		func(*http.Response, []byte) []byte { return []byte("MUT") })
	if err := skip(res); err != nil {
		t.Fatal(err)
	}
	if got := readBody(t, res); got != `<body>x</body>` {
		t.Fatalf("false gate must skip: %q", got)
	}

	// A nil gate always runs; the transform sees the decoded bytes.
	res2 := htmlResponse(`<body>x</body>`, nil)
	run := RewriteHTMLFunc(nil, func(_ *http.Response, b []byte) []byte {
		return bytes.ReplaceAll(b, []byte("x"), []byte("YES"))
	})
	if err := run(res2); err != nil {
		t.Fatal(err)
	}
	if got := readBody(t, res2); got != `<body>YES</body>` {
		t.Fatalf("transform: %q", got)
	}
}

func TestSkipsUnknownEncoding(t *testing.T) {
	res := htmlResponse(`<html><head></head></html>`, http.Header{"Content-Encoding": []string{"br"}})
	if err := InjectAfterHead(`<x/>`)(res); err != nil {
		t.Fatal(err)
	}
	if got := readBody(t, res); got != `<html><head></head></html>` {
		t.Fatalf("brotli body was modified: %q", got)
	}
}
