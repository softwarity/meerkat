package routing

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"text/template"
)

// Answering from a template instead of proxying (ROUTE-17).
//
// The problem it solves: a hosted application asks the gateway "who is signed
// in?" in ITS OWN vocabulary. One expects {"name":…,"authorities":[…]},
// another {"user":{"login":…}}, a third a bare string. Building those shapes
// into Meerkat would mean writing one application's dialect into a product
// meant for all of them, and a second application would need a second endpoint.
//
// So the shape is configuration: a route matches /user, and this brick answers
// it from a template the administrator writes. Nothing to deploy beside the
// gateway, nothing to keep in step with it, and the template travels in the
// configuration export like the rest of the route.
//
// What a template can reach is deliberately tiny: the caller of THIS request
// (routing.Identity) and nothing else. No store, no filesystem, no other
// account. text/template has no loops that do not terminate and no way out of
// its data, so the worst a mistaken template can do is answer something silly
// — and even that is caught when the route is saved, not in production.

// respondFuncs are the helpers a template gets. Small on purpose: each one
// exists because writing it by hand is a bug waiting to happen.
var respondFuncs = template.FuncMap{
	// json renders a value as JSON, quotes and escaping included. It is THE
	// function of this brick: `"name": "{{.Username}}"` looks right and breaks
	// the day a name holds a quote — and names come from directories, not from
	// us. `"name": {{json .Username}}` cannot.
	"json": func(v any) (string, error) {
		b, err := json.Marshal(v)
		if err != nil {
			return "", err
		}
		return string(b), nil
	},
	// join flattens a list into a separated string, for the many services that
	// read roles as "A,B,C".
	"join": func(sep string, list []string) string { return strings.Join(list, sep) },
	// wrap turns a list of strings into a list of one-key objects, which is the
	// shape half the applications out there expect for roles:
	//
	//	{{json (wrap "authority" .Roles)}}  →  [{"authority":"A"},{"authority":"B"}]
	//
	// Written by hand that is a range, an index test for the comma and two
	// nested actions — for something anyone would describe in six words. The
	// loop is still there for the shapes this does not cover.
	"wrap": func(key string, list []string) []map[string]string {
		out := make([]map[string]string, 0, len(list))
		for _, v := range list {
			out = append(out, map[string]string{key: v})
		}
		return out
	},
}

// bodyDoc is what the console shows under the template field. It is the only
// documentation an administrator gets at the moment they need it, so it says
// what is available and shows the one mistake worth warning about.
const bodyDoc = "Go text/template. The caller is available as " +
	"{{.Username}} {{.UserID}} {{.Fullname}} {{.Email}} {{.Tenant}} {{.TenantID}} " +
	"{{.Timezone}} {{.Roles}}, plus {{.SignedIn}} (false when nobody is signed in). " +
	"Functions: json (renders a value as JSON, quotes and escaping included), " +
	"join (e.g. {{join \",\" .Roles}}) and wrap, which turns a list into one-key " +
	"objects: {{json (wrap \"authority\" .Roles)}} gives [{\"authority\":\"A\"}]. " +
	"Write \"name\": {{json .Username}} and NOT \"name\": \"{{.Username}}\" — the second " +
	"breaks on a name holding a quote. Example: " +
	`{"name": {{json .Username}}, "authorities": {{json (wrap "authority" .Roles)}}}`

func init() {
	registerFilter(filterDef{
		Type: "respond", Phase: phaseTerminal, needsIdentity: true,
		Doc: "Answers from a template built on the signed-in caller, instead of proxying. " +
			"Use it to expose the identity endpoint a hosted application expects, in its own shape.",
		Params: []Param{
			{Name: "body", Kind: KindString, Required: true, Literal: true, Doc: bodyDoc},
			{Name: "contentType", Kind: KindString, Default: "application/json; charset=utf-8",
				Doc: "Content-Type of the answer."},
			{Name: "status", Kind: KindInt, Default: 200, Doc: "HTTP status of the answer."},
		},
		compileTerminal: func(a decoded) (http.Handler, error) {
			status := a.num("status")
			if status < 100 || status > 599 {
				return nil, fmt.Errorf("respond: status must be between 100 and 599, got %d", status)
			}
			contentType := a.str("contentType")
			if strings.ContainsAny(contentType, "\r\n") {
				return nil, fmt.Errorf("respond: contentType must not contain a line break")
			}
			tmpl, err := template.New("respond").Funcs(respondFuncs).Parse(a.str("body"))
			if err != nil {
				return nil, fmt.Errorf("respond: %s", readableTemplateError(err))
			}
			// Parsing only catches malformed syntax. A field that does not
			// exist ({{.Usernme}}) parses fine and fails at request time, which
			// is the worst place to find out. Running it once here, against a
			// witness caller, moves that to the moment the route is saved.
			if err := tmpl.Execute(io.Discard, SampleIdentity); err != nil {
				return nil, fmt.Errorf("respond: %s", readableTemplateError(err))
			}
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var buf bytes.Buffer
				if err := tmpl.Execute(&buf, IdentityFrom(r.Context())); err != nil {
					// Validated at save time, so this is close to impossible —
					// and a half-written body is worse than an honest failure.
					http.Error(w, "the route's template could not be rendered", http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", contentType)
				w.Header().Set("Cache-Control", "no-store")
				w.WriteHeader(status)
				_, _ = w.Write(buf.Bytes())
			}), nil
		},
	})
}

// readableTemplateError strips the template machinery's own prefixes, which
// name an internal template and a byte offset the administrator never saw.
func readableTemplateError(err error) string {
	msg := err.Error()
	for _, prefix := range []string{
		`template: respond:`,
		`template: respond: "respond" at <`,
	} {
		msg = strings.TrimPrefix(msg, prefix)
	}
	msg = strings.TrimSpace(msg)
	if i := strings.Index(msg, "executing \"respond\" at "); i >= 0 {
		msg = strings.TrimSpace(msg[:i]) + " " + strings.TrimSpace(msg[i+len("executing \"respond\" at "):])
	}
	return strings.TrimSpace(msg)
}
