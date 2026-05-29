package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
)

func newRandomKeyB64(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func newCipher(t *testing.T) *Cipher {
	t.Helper()
	t.Setenv("QUOKKA_MASTER_KEY", newRandomKeyB64(t))
	t.Setenv("QUOKKA_MASTER_KEY_OLD", "")
	kr, err := LoadKeyring()
	if err != nil {
		t.Fatalf("LoadKeyring: %v", err)
	}
	return NewCipher(kr)
}

func TestLoadKeyring_MissingCurrent(t *testing.T) {
	t.Setenv("QUOKKA_MASTER_KEY", "")
	_, err := LoadKeyring()
	if !errors.Is(err, ErrMasterKeyMissing) {
		t.Fatalf("expected ErrMasterKeyMissing, got %v", err)
	}
}

func TestLoadKeyring_MalformedKey(t *testing.T) {
	t.Setenv("QUOKKA_MASTER_KEY", "!!!notbase64!!!")
	if _, err := LoadKeyring(); err == nil {
		t.Fatal("expected error for malformed key")
	}
}

func TestLoadKeyring_WrongKeyLength(t *testing.T) {
	short := base64.StdEncoding.EncodeToString([]byte("too short"))
	t.Setenv("QUOKKA_MASTER_KEY", short)
	if _, err := LoadKeyring(); err == nil {
		t.Fatal("expected error for wrong-length key")
	}
}

func TestRoundTrip(t *testing.T) {
	c := newCipher(t)
	plain := []byte("sk-fixture-secret-api-key")
	ct, iv, ver, err := c.Encrypt(plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if ver != CurrentKeyVersion {
		t.Fatalf("expected key version %d, got %d", CurrentKeyVersion, ver)
	}
	if len(iv) != NonceSize {
		t.Fatalf("expected IV length %d, got %d", NonceSize, len(iv))
	}
	if bytes.Equal(ct, plain) {
		t.Fatal("ciphertext equals plaintext")
	}
	got, err := c.Decrypt(ct, iv, ver)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, plain)
	}
}

func TestTamperDetection_Ciphertext(t *testing.T) {
	c := newCipher(t)
	ct, iv, ver, err := c.Encrypt([]byte("payload"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	ct[0] ^= 0xff
	if _, err := c.Decrypt(ct, iv, ver); !errors.Is(err, ErrTampered) {
		t.Fatalf("expected ErrTampered, got %v", err)
	}
}

func TestTamperDetection_IV(t *testing.T) {
	c := newCipher(t)
	ct, iv, ver, err := c.Encrypt([]byte("payload"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	iv[0] ^= 0xff
	if _, err := c.Decrypt(ct, iv, ver); !errors.Is(err, ErrTampered) {
		t.Fatalf("expected ErrTampered, got %v", err)
	}
}

func TestUnknownKeyVersion(t *testing.T) {
	c := newCipher(t)
	ct, iv, _, err := c.Encrypt([]byte("payload"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := c.Decrypt(ct, iv, 7); err == nil {
		t.Fatal("expected error for unknown key version")
	}
}

func TestRotation_LegacyDecryptCurrentReencrypt(t *testing.T) {
	// First seed a legacy key, encrypt with it.
	oldKey := newRandomKeyB64(t)
	t.Setenv("QUOKKA_MASTER_KEY", oldKey)
	t.Setenv("QUOKKA_MASTER_KEY_OLD", "")
	oldKR, err := LoadKeyring()
	if err != nil {
		t.Fatalf("LoadKeyring old: %v", err)
	}
	oldC := NewCipher(oldKR)
	ct, iv, _, err := oldC.Encrypt([]byte("api-key-1"))
	if err != nil {
		t.Fatalf("old encrypt: %v", err)
	}

	// Now rotate: set new key as current, old key as legacy.
	t.Setenv("QUOKKA_MASTER_KEY", newRandomKeyB64(t))
	t.Setenv("QUOKKA_MASTER_KEY_OLD", oldKey)
	newKR, err := LoadKeyring()
	if err != nil {
		t.Fatalf("LoadKeyring new: %v", err)
	}
	newC := NewCipher(newKR)

	// Legacy row uses key_version=0; decrypt should still work.
	plain, err := newC.Decrypt(ct, iv, LegacyKeyVersion)
	if err != nil {
		t.Fatalf("decrypt legacy: %v", err)
	}
	if string(plain) != "api-key-1" {
		t.Fatalf("decrypt mismatch: %q", plain)
	}

	// Re-encrypt under the current key.
	ct2, iv2, ver, err := newC.Encrypt(plain)
	if err != nil {
		t.Fatalf("reencrypt: %v", err)
	}
	if ver != CurrentKeyVersion {
		t.Fatalf("re-encrypt version: %d", ver)
	}
	got, err := newC.Decrypt(ct2, iv2, ver)
	if err != nil {
		t.Fatalf("decrypt new: %v", err)
	}
	if string(got) != "api-key-1" {
		t.Fatalf("final mismatch: %q", got)
	}
}

func TestCorruptedMasterKey_GetReturnsError(t *testing.T) {
	c := newCipher(t)
	ct, iv, ver, err := c.Encrypt([]byte("payload"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// Build a fresh cipher with a different master key under the same version.
	t.Setenv("QUOKKA_MASTER_KEY", newRandomKeyB64(t))
	kr2, err := LoadKeyring()
	if err != nil {
		t.Fatalf("LoadKeyring2: %v", err)
	}
	c2 := NewCipher(kr2)
	if _, err := c2.Decrypt(ct, iv, ver); !errors.Is(err, ErrTampered) {
		t.Fatalf("expected ErrTampered with wrong master key, got %v", err)
	}
}
