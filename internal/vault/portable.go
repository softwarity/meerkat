package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// The vault as a file (VAULT-03).
//
// A configuration is public and carries no secret; this is the other half, and
// it is the opposite in every way. It holds the values themselves, it is
// encrypted with a passphrase the gateway never stores, and it is NOT something
// anyone should version: it exists to bootstrap an environment or to move a
// gateway, then to be deleted.
//
// The file writes its own recipe in clear - format version, KDF, its
// parameters, the salt, the nonce - because it will outlive the binary that
// produced it by years, and a parameter changed in a later release must not
// make an old export unreadable.
//
// The passphrase is the whole security of this file, and this file concentrates
// every secret of an installation: it is the most rewarding target there is.
// MinPassphrase is a floor, not an opinion - the console offers to generate one
// precisely so nobody types the product name followed by the year.

// PortableVersion is the format version of an encrypted vault file.
const PortableVersion = 1

// MinPassphrase is the shortest passphrase accepted. Short enough not to be in
// the way, long enough that the answer to "why was it refused" is obvious.
const MinPassphrase = 12

// Argon2id parameters. Written into every file so a change here never orphans
// an export made before it.
const (
	kdfTime    = 3
	kdfMemory  = 64 * 1024 // KiB
	kdfThreads = 4
	kdfKeyLen  = 32
	saltLen    = 16
)

// PortableEntry is one vault entry as it travels. Timestamps are left out: they
// describe the install that wrote them, not the secret.
type PortableEntry struct {
	Name        string   `json:"name"`
	Kind        string   `json:"kind"`
	Scope       string   `json:"scope"`
	Value       string   `json:"value"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// PortableFile is what lands on disk: a readable header and one sealed blob.
type PortableFile struct {
	// Meerkat names what this is, for whoever finds the file later with no
	// context at all.
	Meerkat string `json:"meerkat"`
	Version int    `json:"version"`
	KDF     KDF    `json:"kdf"`
	Cipher  string `json:"cipher"`
	Nonce   string `json:"nonce"`
	// Payload is base64(AES-256-GCM(entries as JSON)).
	Payload string `json:"payload"`
}

// KDF records how the key was derived from the passphrase.
type KDF struct {
	Name    string `json:"name"`
	Salt    string `json:"salt"`
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"`
	Threads uint8  `json:"threads"`
}

// SealVault encrypts entries under passphrase.
func SealVault(entries []PortableEntry, passphrase string) (*PortableFile, error) {
	if err := CheckPassphrase(passphrase); err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("vault: there is nothing to export")
	}
	plain, err := json.Marshal(entries)
	if err != nil {
		return nil, fmt.Errorf("vault: encode entries: %w", err)
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("vault: salt: %w", err)
	}
	aead, err := aeadFor(passphrase, salt)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("vault: nonce: %w", err)
	}
	return &PortableFile{
		Meerkat: "vault",
		Version: PortableVersion,
		KDF: KDF{
			Name: "argon2id", Salt: base64.StdEncoding.EncodeToString(salt),
			Time: kdfTime, Memory: kdfMemory, Threads: kdfThreads,
		},
		Cipher:  "aes-256-gcm",
		Nonce:   base64.StdEncoding.EncodeToString(nonce),
		Payload: base64.StdEncoding.EncodeToString(aead.Seal(nil, nonce, plain, nil)),
	}, nil
}

// OpenVault decrypts a file produced by SealVault.
//
// A wrong passphrase and a tampered file fail the same way, because GCM
// authenticates: there is nothing to tell apart and nothing to leak.
func OpenVault(file *PortableFile, passphrase string) ([]PortableEntry, error) {
	switch {
	case file == nil:
		return nil, fmt.Errorf("vault: no file")
	case file.Meerkat != "vault":
		return nil, fmt.Errorf("vault: this is not a Meerkat vault file")
	case file.Version > PortableVersion:
		return nil, fmt.Errorf("vault: this file is version %d and this Meerkat reads up to %d",
			file.Version, PortableVersion)
	case file.KDF.Name != "argon2id":
		return nil, fmt.Errorf("vault: unknown key derivation %q (this Meerkat knows argon2id)",
			file.KDF.Name)
	case file.Cipher != "aes-256-gcm":
		return nil, fmt.Errorf("vault: unknown cipher %q (this Meerkat knows aes-256-gcm)",
			file.Cipher)
	case strings.TrimSpace(passphrase) == "":
		return nil, fmt.Errorf("vault: this file needs its passphrase")
	}
	salt, err := base64.StdEncoding.DecodeString(file.KDF.Salt)
	if err != nil || len(salt) == 0 {
		return nil, fmt.Errorf("vault: the file's salt is unreadable")
	}
	nonce, err := base64.StdEncoding.DecodeString(file.Nonce)
	if err != nil {
		return nil, fmt.Errorf("vault: the file's nonce is unreadable")
	}
	payload, err := base64.StdEncoding.DecodeString(file.Payload)
	if err != nil {
		return nil, fmt.Errorf("vault: the file's payload is unreadable")
	}
	// The file's OWN parameters, not the constants above: that is the point of
	// writing them down.
	aead, err := aeadWith(passphrase, salt, file.KDF)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("vault: the file's nonce has the wrong size")
	}
	plain, err := aead.Open(nil, nonce, payload, nil)
	if err != nil {
		return nil, fmt.Errorf("vault: wrong passphrase, or the file has been altered")
	}
	var entries []PortableEntry
	if err := json.Unmarshal(plain, &entries); err != nil {
		return nil, fmt.Errorf("vault: the decrypted content is not a vault export: %w", err)
	}
	for i, e := range entries {
		if !NameOK.MatchString(e.Name) {
			return nil, fmt.Errorf("vault: entry %d is named %q, which is not a usable name", i+1, e.Name)
		}
		if !ValidKind(e.Kind) {
			return nil, fmt.Errorf("vault: entry %q is of kind %q (allowed: %s, %s)",
				e.Name, e.Kind, KindValue, KindSecret)
		}
		if !ValidScope(e.Scope) {
			return nil, fmt.Errorf("vault: entry %q belongs to scope %q, which is not a scope",
				e.Name, e.Scope)
		}
	}
	return entries, nil
}

// CheckPassphrase refuses what would make the encryption decorative.
func CheckPassphrase(passphrase string) error {
	if n := utf8.RuneCountInString(passphrase); n < MinPassphrase {
		return fmt.Errorf("vault: a passphrase of %d characters is too short: this one file holds "+
			"every secret of the installation, so it needs at least %d "+
			"(the console offers to generate one)", n, MinPassphrase)
	}
	return nil
}

// GeneratePassphrase mints one worth using: 24 random bytes, url-safe, so it
// survives a copy through a terminal, a chat and a password manager.
func GeneratePassphrase() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("vault: generate passphrase: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func aeadFor(passphrase string, salt []byte) (cipher.AEAD, error) {
	return aeadWith(passphrase, salt, KDF{Time: kdfTime, Memory: kdfMemory, Threads: kdfThreads})
}

func aeadWith(passphrase string, salt []byte, kdf KDF) (cipher.AEAD, error) {
	// Guard the parameters a file carries: they drive an allocation, and a file
	// claiming 16 GiB of memory would take the gateway down before it could
	// even report a wrong passphrase.
	if kdf.Time == 0 || kdf.Memory == 0 || kdf.Threads == 0 || kdf.Memory > 1<<20 {
		return nil, fmt.Errorf("vault: the file's key-derivation parameters are out of range")
	}
	key := argon2.IDKey([]byte(passphrase), salt, kdf.Time, kdf.Memory, kdf.Threads, kdfKeyLen)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("vault: cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("vault: gcm: %w", err)
	}
	// The derived key has done its work; do not leave it lying in memory longer
	// than needed.
	subtle.ConstantTimeCopy(1, key, make([]byte, len(key)))
	return aead, nil
}
