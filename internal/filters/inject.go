// Package filters holds Meerkat's response/request filters. The first one is
// the app-gateway signature move: injecting gateway-provided content into the
// HTML pages of proxied applications (UIF-02 in the requirements).
package filters

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
)

// maxInjectableBody caps how much of a response we are willing to buffer to
// rewrite it. Bigger HTML responses pass through untouched.
const maxInjectableBody = 20 << 20 // 20 MiB, the V1 ceiling

var headTag = regexp.MustCompile(`(?i)<head[^>]*>`)

// InjectAfterHead returns a ReverseProxy ModifyResponse function that inserts
// fragment right after the opening <head> tag of HTML responses. Non-HTML
// responses and unsupported encodings pass through untouched. Gzip bodies are
// decoded and re-encoded; the skeleton does not handle brotli yet.
func InjectAfterHead(fragment string) func(*http.Response) error {
	return InjectAfterHeadFunc(func(*http.Response) string { return fragment })
}

// InjectAfterHeadFunc is InjectAfterHead with a PER-RESPONSE fragment: f runs
// on each HTML response (res.Request carries the caller's cookies/context, so
// the fragment can be session-specific). An empty fragment skips the rewrite
// WITHOUT buffering the body (the common anonymous case stays cheap).
func InjectAfterHeadFunc(f func(*http.Response) string) func(*http.Response) error {
	return func(res *http.Response) error {
		if !isHTML(res) {
			return nil
		}
		frag := []byte(f(res))
		if len(frag) == 0 {
			return nil
		}
		return rewriteHTMLBody(res, func(body []byte) []byte { return injectAfterHead(body, frag) })
	}
}

// RewriteHTMLFunc buffers each HTML response and hands the DECODED bytes to f,
// which returns the rewritten bytes (used for server-side stamping that must
// edit an existing tag, not just insert after <head>). gate, when non-nil,
// runs first and skips the whole thing (no body buffering) when it returns
// false - pass a cheap session check so anonymous requests stay untouched.
// Non-HTML and unsupported encodings pass through.
func RewriteHTMLFunc(gate func(*http.Response) bool, f func(res *http.Response, body []byte) []byte) func(*http.Response) error {
	return func(res *http.Response) error {
		if !isHTML(res) {
			return nil
		}
		if gate != nil && !gate(res) {
			return nil
		}
		return rewriteHTMLBody(res, func(body []byte) []byte { return f(res, body) })
	}
}

// rewriteHTMLBody handles the read/decode/transform/re-encode plumbing shared
// by the HTML rewriters. Unsupported encodings, oversized or broken bodies pass
// through untouched.
func rewriteHTMLBody(res *http.Response, transform func([]byte) []byte) error {
	encoding := res.Header.Get("Content-Encoding")
	if encoding != "" && encoding != "gzip" {
		return nil // brotli/zstd: pass through for now
	}
	if res.ContentLength > maxInjectableBody {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxInjectableBody+1))
	closeErr := res.Body.Close()
	if err != nil {
		return fmt.Errorf("rewrite: read body: %w", err)
	}
	if closeErr != nil {
		return fmt.Errorf("rewrite: close body: %w", closeErr)
	}
	if len(body) > maxInjectableBody {
		// Too big to rewrite: restore what we read, untouched.
		res.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}
	plain := body
	if encoding == "gzip" {
		if plain, err = gunzip(body); err != nil {
			// Broken encoding: hand the original bytes back untouched.
			res.Body = io.NopCloser(bytes.NewReader(body))
			return nil
		}
	}
	out := transform(plain)
	if encoding == "gzip" {
		if out, err = gzipBytes(out); err != nil {
			return fmt.Errorf("rewrite: gzip: %w", err)
		}
	}
	res.Body = io.NopCloser(bytes.NewReader(out))
	res.ContentLength = int64(len(out))
	res.Header.Set("Content-Length", strconv.Itoa(len(out)))
	return nil
}

func isHTML(res *http.Response) bool {
	ct := res.Header.Get("Content-Type")
	return len(ct) >= 9 && ct[:9] == "text/html"
}

// injectAfterHead inserts frag after the first opening <head> tag, or before
// the whole document when no <head> is found.
func injectAfterHead(body, frag []byte) []byte {
	loc := headTag.FindIndex(body)
	out := make([]byte, 0, len(body)+len(frag))
	if loc == nil {
		out = append(out, frag...)
		return append(out, body...)
	}
	out = append(out, body[:loc[1]]...)
	out = append(out, frag...)
	return append(out, body[loc[1]:]...)
}

func gunzip(data []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	plain, err := io.ReadAll(zr)
	if cerr := zr.Close(); err == nil {
		err = cerr
	}
	return plain, err
}

func gzipBytes(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
