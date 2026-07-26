package admin

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// Control-plane tokens: root-only to mint, they authenticate on the admin port
// via Bearer (no cookie), and revoking kills them at once.
func TestAdminTokens(t *testing.T) {
	f := setup(t)

	// Non-root cannot mint a control-plane token.
	if code, _ := f.call(t, "POST", "/api/admin-tokens", `{"name":"cli"}`, f.plainC); code != http.StatusForbidden {
		t.Fatalf("non-root minting must 403: %d", code)
	}

	// root mints one; the clear value is returned exactly once.
	code, body := f.call(t, "POST", "/api/admin-tokens", `{"name":"cli"}`, f.rootC)
	if code != http.StatusCreated {
		t.Fatalf("root mint: %d %s", code, body)
	}
	var created struct{ Token, ID string }
	if err := json.Unmarshal([]byte(body), &created); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(created.Token, "mk_") {
		t.Fatalf("token shape: %q", created.Token)
	}

	// It authenticates on the ADMIN port with a Bearer header and no cookie.
	if code, me := f.bearer(t, "GET", "/api/me", created.Token); code != http.StatusOK || !strings.Contains(me, `"username":"root"`) {
		t.Fatalf("admin token must authenticate as root: %d %s", code, me)
	}

	// It is listed, and revoking it kills it immediately.
	if _, list := f.call(t, "GET", "/api/admin-tokens", "", f.rootC); !strings.Contains(list, created.ID) {
		t.Fatalf("token must be listed: %s", list)
	}
	if code, _ := f.call(t, "DELETE", "/api/admin-tokens/"+created.ID, "", f.rootC); code != http.StatusNoContent {
		t.Fatalf("revoke: %d", code)
	}
	if code, _ := f.bearer(t, "GET", "/api/me", created.Token); code == http.StatusOK {
		t.Fatalf("a revoked token must not authenticate: %d", code)
	}
}

// bearer calls the admin server with an Authorization: Bearer header and no
// cookie (the headless path).
func (f fixture) bearer(t *testing.T, method, path, token string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, f.adminSrv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	return res.StatusCode, string(b)
}
