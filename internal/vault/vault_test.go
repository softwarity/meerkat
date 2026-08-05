package vault

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	key, err := LoadOrCreateKey(t.TempDir(), "")
	if err != nil {
		t.Fatalf("LoadOrCreateKey: %v", err)
	}
	c, err := NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	const plain = "hunter2 · with unicode ✓"
	blob, err := c.Seal(plain)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if strings.Contains(blob, "hunter2") {
		t.Fatalf("ciphertext leaks the plain value: %q", blob)
	}
	// A random nonce per seal: the same value never yields the same blob.
	again, _ := c.Seal(plain)
	if again == blob {
		t.Fatal("two seals of the same value produced the same ciphertext")
	}
	got, err := c.Open(blob)
	if err != nil || got != plain {
		t.Fatalf("Open = %q, %v; want %q", got, err, plain)
	}

	// A different key cannot open it (GCM authenticates).
	other, _ := LoadOrCreateKey(t.TempDir(), "")
	oc, _ := NewCipher(other)
	if _, err := oc.Open(blob); err == nil {
		t.Fatal("a foreign key opened the ciphertext")
	}
}

// The key file is created once, reused after, and never world-readable.
func TestMasterKeyFile(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrCreateKey(dir, "")
	if err != nil {
		t.Fatalf("LoadOrCreateKey: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, KeyFileName))
	if err != nil {
		t.Fatalf("key file: %v", err)
	}
	// Windows has no POSIX permission bits: the file lands 0666 whatever is
	// asked, and checking it there would only assert the platform. Worth
	// knowing rather than hiding: on Windows the key is NOT protected by its
	// mode, so supplying it through MEERKAT_VAULT_KEY matters more there.
	if perm := info.Mode().Perm(); perm != 0o600 && runtime.GOOS != "windows" {
		t.Fatalf("key file mode = %v, want 0600", perm)
	}
	second, err := LoadOrCreateKey(dir, "")
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatal("the key file was not reused")
	}
	// The environment wins over the file, and rejects a bad key loudly.
	env, err := LoadOrCreateKey(dir, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	if err != nil || len(env) != 32 || reflect.DeepEqual(env, first) {
		t.Fatalf("env key not honoured: %v", err)
	}
	if _, err := LoadOrCreateKey(dir, "too-short"); err == nil {
		t.Fatal("a malformed env key was accepted")
	}
}

func TestRefsAndExpand(t *testing.T) {
	const s = `https://$host:8080/${path}?k=$host&lit=$$notaref`
	if got, want := Refs(s), []string{"host", "path"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Refs = %v, want %v", got, want)
	}
	vals := map[string]string{"host": "api.internal", "path": "v1"}
	out, missing := Expand(s, func(n string) (string, bool) { v, ok := vals[n]; return v, ok })
	if want := `https://api.internal:8080/v1?k=api.internal&lit=$notaref`; out != want {
		t.Fatalf("Expand = %q, want %q", out, want)
	}
	if len(missing) != 0 {
		t.Fatalf("unexpected missing: %v", missing)
	}

	// An unknown reference stays VERBATIM and is reported: a typo must not
	// quietly become an empty upstream.
	out, missing = Expand("http://$nope/x", func(string) (string, bool) { return "", false })
	if out != "http://$nope/x" || !reflect.DeepEqual(missing, []string{"nope"}) {
		t.Fatalf("Expand(missing) = %q, %v", out, missing)
	}
}

// TestRefName: the rule a SECRET field is judged by. A value that merely
// contains a reference is a literal, because what would leak is the rest of it.
func TestRefName(t *testing.T) {
	for in, want := range map[string]string{
		"$smtp-password":   "smtp-password",
		"${smtp-password}": "smtp-password",
		"$a.b_c":           "a.b_c",
		// Literals, every one of them: a fragment, a concatenation, an escaped
		// $, and a password that simply happens to start with a dollar.
		"http://${host}:8080": "",
		"${a}${b}":            "",
		"x-$token":            "",
		"$$notaref":           "",
		"$2y$10$abcdefg":      "",
		" $host":              "",
		"":                    "",
	} {
		if got := RefName(in); got != want {
			t.Fatalf("RefName(%q) = %q, want %q", in, got, want)
		}
		if IsRef(in) != (want != "") {
			t.Fatalf("IsRef(%q) disagrees with RefName", in)
		}
	}
	// What Ref writes must read back as the same name, or a stash would store
	// something the gateway cannot resolve.
	if got := RefName(Ref("smtp-password")); got != "smtp-password" {
		t.Fatalf("Ref/RefName round trip = %q", got)
	}
}

func TestNameOK(t *testing.T) {
	for _, ok := range []string{"host", "smtp-password", "db.url", "a_b1"} {
		if !NameOK.MatchString(ok) {
			t.Fatalf("%q should be a valid name", ok)
		}
	}
	for _, bad := range []string{"", "1st", "with space", "wi/th", "é", "a$b"} {
		if NameOK.MatchString(bad) {
			t.Fatalf("%q should be rejected", bad)
		}
	}
}
