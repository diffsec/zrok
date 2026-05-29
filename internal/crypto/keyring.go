// Package crypto provides AES-256-GCM encryption for at-rest secrets.
//
// Two env vars compose the keyring:
//   - QUOKKA_MASTER_KEY      32 random bytes base64-encoded; current key.
//   - QUOKKA_MASTER_KEY_OLD  optional; legacy key for decrypt-only during rotation.
//
// Each row stores ciphertext + 12-byte IV + key_version. The Cipher knows which
// physical key corresponds to which key_version via the Keyring.
package crypto

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
)

const (
	envCurrent = "QUOKKA_MASTER_KEY"
	envLegacy  = "QUOKKA_MASTER_KEY_OLD"

	// CurrentKeyVersion is the version that fresh encryptions use. v1
	// always means the QUOKKA_MASTER_KEY env value. The legacy slot is v0.
	CurrentKeyVersion int16 = 1
	LegacyKeyVersion  int16 = 0
)

// ErrMasterKeyMissing is returned when QUOKKA_MASTER_KEY is unset.
var ErrMasterKeyMissing = errors.New("QUOKKA_MASTER_KEY is not set")

// Keyring resolves key versions to raw 32-byte AES keys.
type Keyring struct {
	current []byte
	legacy  []byte // may be nil
}

// LoadKeyring reads the env vars and constructs a keyring. Boots fail if the
// current key is unset or malformed.
func LoadKeyring() (*Keyring, error) {
	cur := os.Getenv(envCurrent)
	if cur == "" {
		return nil, ErrMasterKeyMissing
	}
	curRaw, err := decodeKey(cur)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", envCurrent, err)
	}
	kr := &Keyring{current: curRaw}
	if legacy := os.Getenv(envLegacy); legacy != "" {
		legRaw, err := decodeKey(legacy)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", envLegacy, err)
		}
		kr.legacy = legRaw
	}
	return kr, nil
}

// CurrentKey returns the key used for fresh encryptions.
func (k *Keyring) CurrentKey() []byte { return k.current }

// CurrentVersion is the version label written with new ciphertexts.
func (k *Keyring) CurrentVersion() int16 { return CurrentKeyVersion }

// KeyForVersion returns the key matching a stored key_version. Unknown
// versions yield an error rather than guessing.
func (k *Keyring) KeyForVersion(v int16) ([]byte, error) {
	switch v {
	case CurrentKeyVersion:
		return k.current, nil
	case LegacyKeyVersion:
		if k.legacy == nil {
			return nil, fmt.Errorf("key_version %d (legacy) requested but %s is not set", v, envLegacy)
		}
		return k.legacy, nil
	default:
		return nil, fmt.Errorf("unknown key_version %d", v)
	}
}

func decodeKey(s string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		// try url-safe encoding as a fallback
		raw2, err2 := base64.RawStdEncoding.DecodeString(s)
		if err2 == nil {
			raw = raw2
		} else {
			return nil, fmt.Errorf("base64 decode: %w", err)
		}
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("expected 32 bytes after base64 decode, got %d", len(raw))
	}
	return raw, nil
}
