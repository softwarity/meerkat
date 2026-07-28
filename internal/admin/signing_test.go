package admin

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"strings"
	"testing"
)

// TestIdentityPreviewSignedIsVerifiable is the whole point of the preview: the
// token it returns is REALLY signed by the gateway key, so pasting it into a
// JWT debugger with the PEM it hands out verifies. Also checks the headers
// mechanism renders the mapped names and the roles format.
func TestIdentityPreviewSignedIsVerifiable(t *testing.T) {
	f := setup(t)

	// Headers mechanism: mapped names, roles as a JSON array.
	body := `{"routeName":"orders","identity":{"mechanism":"headers","attributes":[
	  {"field":"username","as":"X-User"},{"field":"roles","asJson":true}]}}`
	code, out := f.call(t, "POST", "/api/identity/preview", body, f.rootC)
	if code != http.StatusOK {
		t.Fatalf("headers preview: %d %s", code, out)
	}
	if !strings.Contains(out, `"name":"X-User"`) || !strings.Contains(out, `"value":"jdoe"`) {
		t.Fatalf("mapped header missing: %s", out)
	}
	if !strings.Contains(out, `[\"role-a\",\"role-b\"]`) {
		t.Fatalf("roles not rendered as a JSON array: %s", out)
	}

	// Non-root cannot mint a preview token.
	if code, _ := f.call(t, "POST", "/api/identity/preview", body, f.plainC); code != http.StatusForbidden {
		t.Fatalf("preview authz: %d, want 403", code)
	}

	// An invalid config is refused exactly like a save would refuse it.
	bad := `{"routeName":"orders","identity":{"mechanism":"headers","attributes":[{"field":"shoesize"}]}}`
	if code, out := f.call(t, "POST", "/api/identity/preview", bad, f.rootC); code != http.StatusUnprocessableEntity {
		t.Fatalf("bad attribute: %d %s, want 422", code, out)
	}

	// signed-jwt: the token verifies against the PEM returned alongside it.
	signed := `{"routeName":"orders","identity":{"mechanism":"signed-jwt","algorithm":"ES256",
	  "attributes":[{"field":"username","as":"preferred_username"}]}}`
	code, out = f.call(t, "POST", "/api/identity/preview", signed, f.rootC)
	if code != http.StatusOK {
		t.Fatalf("signed preview: %d %s", code, out)
	}
	var res struct {
		Token     string         `json:"token"`
		Claims    map[string]any `json:"claims"`
		Algorithm string         `json:"algorithm"`
		Kid       string         `json:"kid"`
		PublicPem string         `json:"publicPem"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.Algorithm != "ES256" || res.Kid == "" {
		t.Fatalf("missing key material: %+v", res)
	}
	if res.Claims["aud"] != "orders" || res.Claims["preferred_username"] != "jdoe" {
		t.Fatalf("claims wrong: %+v", res.Claims)
	}

	block, _ := pem.Decode([]byte(res.PublicPem))
	if block == nil {
		t.Fatalf("publicPem is not a PEM block: %q", res.PublicPem)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	parts := strings.Split(res.Token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", res.Token)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		t.Fatalf("bad signature segment: %v (%d bytes)", err, len(sig))
	}
	h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub.(*ecdsa.PublicKey), h[:], r, s) {
		t.Fatal("preview token does not verify against the PEM it ships with")
	}
}
