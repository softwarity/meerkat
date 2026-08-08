package routing

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func compileRespond(t *testing.T, args map[string]any) (http.Handler, error) {
	t.Helper()
	cf, err := CompileFilters([]Spec{{Type: "respond", Args: args}})
	return cf.Terminal, err
}

func serve(t *testing.T, h http.Handler, id Identity) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/user", nil)
	req = req.WithContext(WithIdentity(req.Context(), id))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Result()
}

// The case this brick was built for: NEO's portal asks the gateway who is
// signed in, in its own shape. No Go written for it - a route and a template.
func TestRespondRendersTheApplicationsOwnShape(t *testing.T) {
	h, err := compileRespond(t, map[string]any{
		"body": `{"name": {{json .Username}}, "isPasswordUpdatable": false, ` +
			`"authorities": [{{range $i, $r := .Roles}}{{if $i}},{{end}}{"authority": {{json $r}}}{{end}}]}`,
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	res := serve(t, h, Identity{Username: "alice", Roles: []string{"ROLE_APP_CLIM", "ROLE_APP_SWAGGER"}})
	defer func() { _ = res.Body.Close() }()

	if ct := res.Header.Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Fatalf("Content-Type %q", ct)
	}
	var got struct {
		Name                string `json:"name"`
		IsPasswordUpdatable bool   `json:"isPasswordUpdatable"`
		Authorities         []struct {
			Authority string `json:"authority"`
		} `json:"authorities"`
	}
	if err := json.NewDecoder(res.Body).Decode(&got); err != nil {
		t.Fatalf("the answer is not the JSON the application expects: %v", err)
	}
	if got.Name != "alice" || len(got.Authorities) != 2 || got.Authorities[1].Authority != "ROLE_APP_SWAGGER" {
		t.Fatalf("got %+v", got)
	}
}

// The reason `json` exists. A name comes from a directory, not from us: written
// by hand between quotes, the first apostrophe or quote in it produces a
// document nobody can parse - and this is the field an attacker controls.
func TestRespondEscapesWhatItRenders(t *testing.T) {
	h, err := compileRespond(t, map[string]any{"body": `{"name": {{json .Username}}}`})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	res := serve(t, h, Identity{Username: `he said "hi"` + "\n\\"})
	defer func() { _ = res.Body.Close() }()

	var got map[string]string
	if err := json.NewDecoder(res.Body).Decode(&got); err != nil {
		t.Fatalf("a quote in a username broke the document: %v", err)
	}
	if got["name"] != `he said "hi"`+"\n\\" {
		t.Fatalf("value mangled: %q", got["name"])
	}
}

// A template is checked when the ROUTE IS SAVED, not when a user hits it. A
// typo in a field name parses fine and would otherwise fail in production, at
// the worst possible moment, on the one endpoint an application polls.
func TestRespondRefusesABrokenTemplateAtSaveTime(t *testing.T) {
	for _, tc := range []struct {
		name, body, wants string
	}{
		{"action left open", `{"name": {{json .Username`, "unclosed action"},
		{"action closed with one brace", `{"name": {{json .Username}`, "bad character"},
		{"field that does not exist", `{"name": {{json .Usernme}}}`, "Usernme"},
		{"unknown function", `{{whoami .Username}}`, "whoami"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := compileRespond(t, map[string]any{"body": tc.body})
			if err == nil {
				t.Fatal("accepted a template that cannot work")
			}
			if !strings.Contains(err.Error(), tc.wants) {
				t.Fatalf("the error must name what is wrong (%q): %v", tc.wants, err)
			}
		})
	}
}

// An anonymous caller still reaches a route with no gateway rule, and the
// template decides what they are told - which is how one route serves both the
// signed-in shape and the public one.
func TestRespondSpeaksAboutAnonymousCallers(t *testing.T) {
	h, err := compileRespond(t, map[string]any{
		"body": `{"name": {{if .SignedIn}}{{json .Username}}{{else}}"anonymous"{{end}}}`,
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	res := serve(t, h, Identity{})
	defer func() { _ = res.Body.Close() }()
	var got map[string]string
	if err := json.NewDecoder(res.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got["name"] != "anonymous" {
		t.Fatalf("got %q", got["name"])
	}
}

func TestRespondOptions(t *testing.T) {
	t.Run("plain text and a chosen status", func(t *testing.T) {
		h, err := compileRespond(t, map[string]any{
			"body": "{{.Username}}", "contentType": "text/plain; charset=utf-8", "status": 200,
		})
		if err != nil {
			t.Fatal(err)
		}
		res := serve(t, h, Identity{Username: "alice"})
		defer func() { _ = res.Body.Close() }()
		body := make([]byte, 16)
		n, _ := res.Body.Read(body)
		if string(body[:n]) != "alice" {
			t.Fatalf("got %q", body[:n])
		}
		if res.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("an answer about who is signed in must not be cached")
		}
	})

	t.Run("roles as a separated string", func(t *testing.T) {
		h, err := compileRespond(t, map[string]any{"body": `{{join "," .Roles}}`})
		if err != nil {
			t.Fatal(err)
		}
		res := serve(t, h, Identity{Roles: []string{"A", "B"}})
		defer func() { _ = res.Body.Close() }()
		buf := make([]byte, 8)
		n, _ := res.Body.Read(buf)
		if string(buf[:n]) != "A,B" {
			t.Fatalf("got %q", buf[:n])
		}
	})

	t.Run("a header cannot be smuggled through the content type", func(t *testing.T) {
		if _, err := compileRespond(t, map[string]any{
			"body": "x", "contentType": "text/plain\r\nX-Evil: 1",
		}); err == nil {
			t.Fatal("accepted a content type carrying a line break")
		}
	})

	t.Run("an impossible status is refused", func(t *testing.T) {
		if _, err := compileRespond(t, map[string]any{"body": "x", "status": 999}); err == nil {
			t.Fatal("accepted status 999")
		}
	})
}

// wrap exists because the shape it produces is what half the applications
// expect for roles, and writing it by hand is a range plus an index test for
// the comma - six words of intent, four lines of template.
func TestRespondWrapsAListIntoObjects(t *testing.T) {
	h, err := compileRespond(t, map[string]any{
		"body": `{"name": {{json .Username}}, "isPasswordUpdatable": false, "authorities": {{json (wrap "authority" .Roles)}}}`,
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	res := serve(t, h, Identity{Username: "admin", Roles: []string{"ROLE_APP_CLIM", "ROLE_APP_SWAGGER"}})
	defer func() { _ = res.Body.Close() }()

	var got struct {
		Name        string `json:"name"`
		Authorities []struct {
			Authority string `json:"authority"`
		} `json:"authorities"`
	}
	if err := json.NewDecoder(res.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Name != "admin" || len(got.Authorities) != 2 ||
		got.Authorities[0].Authority != "ROLE_APP_CLIM" || got.Authorities[1].Authority != "ROLE_APP_SWAGGER" {
		t.Fatalf("got %+v", got)
	}

	// No role at all must still be a list, not null: an application reading
	// authorities.length would break on null.
	empty := serve(t, h, Identity{Username: "newcomer"})
	defer func() { _ = empty.Body.Close() }()
	if err := json.NewDecoder(empty.Body).Decode(&got); err != nil {
		t.Fatalf("an account with no role produced unusable JSON: %v", err)
	}
	if got.Authorities == nil || len(got.Authorities) != 0 {
		t.Fatalf("want an empty list, got %v", got.Authorities)
	}
}
