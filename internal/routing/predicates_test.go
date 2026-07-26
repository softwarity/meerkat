package routing

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The SCG time predicates: after/before/between evaluate against now; bad
// datetimes and inverted bounds fail at compile time.
func TestTimePredicates(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	past, future := "2000-01-01T00:00:00Z", "2100-01-01T00:00:00Z"

	match := func(spec Spec) bool {
		t.Helper()
		cp, err := CompilePredicates([]Spec{spec})
		if err != nil {
			t.Fatalf("compile %v: %v", spec, err)
		}
		return cp.Match(req)
	}
	if !match(Spec{Type: "after", Args: map[string]any{"datetime": past}}) {
		t.Fatal("after(past) must match now")
	}
	if match(Spec{Type: "after", Args: map[string]any{"datetime": future}}) {
		t.Fatal("after(future) must not match now")
	}
	if !match(Spec{Type: "before", Args: map[string]any{"datetime": future}}) {
		t.Fatal("before(future) must match now")
	}
	if !match(Spec{Type: "between", Args: map[string]any{"datetime1": past, "datetime2": future}}) {
		t.Fatal("between(past, future) must match now")
	}
	if _, err := CompilePredicates([]Spec{{Type: "after", Args: map[string]any{"datetime": "tomorrow"}}}); err == nil {
		t.Fatal("bad datetime accepted")
	}
	if _, err := CompilePredicates([]Spec{{Type: "between",
		Args: map[string]any{"datetime1": future, "datetime2": past}}}); err == nil {
		t.Fatal("inverted between accepted")
	}
}

// x-forwarded-remote-addr matches the RIGHTMOST X-Forwarded-For entry.
func TestXForwardedRemoteAddr(t *testing.T) {
	cp, err := CompilePredicates([]Spec{{Type: "x-forwarded-remote-addr",
		Args: map[string]any{"cidrs": []any{"10.0.0.0/8"}}}})
	if err != nil {
		t.Fatal(err)
	}
	mk := func(xff string) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}
	if !cp.Match(mk("203.0.113.9, 10.1.2.3")) {
		t.Fatal("rightmost 10.x must match")
	}
	if cp.Match(mk("10.1.2.3, 203.0.113.9")) {
		t.Fatal("rightmost public address must not match")
	}
	if cp.Match(mk("")) {
		t.Fatal("no X-Forwarded-For must not match")
	}
}
