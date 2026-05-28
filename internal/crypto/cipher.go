package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// NonceSize is the GCM standard 12-byte nonce.
const NonceSize = 12

// ErrTampered is returned when ciphertext or IV fails authentication.
var ErrTampered = errors.New("ciphertext authentication failed")

// Cipher wraps a Keyring and provides AES-GCM Encrypt/Decrypt over plaintext.
type Cipher struct {
	kr *Keyring
}

// NewCipher constructs a Cipher from a loaded keyring.
func NewCipher(kr *Keyring) *Cipher {
	return &Cipher{kr: kr}
}

// Encrypt encrypts plaintext with the current key. Returns ciphertext, the
// 12-byte IV, and the key_version to record alongside.
func (c *Cipher) Encrypt(plaintext []byte) (ciphertext, iv []byte, keyVer int16, err error) {
	block, err := aes.NewCipher(c.kr.CurrentKey())
	if err != nil {
		return nil, nil, 0, fmt.Errorf("aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("gcm: %w", err)
	}
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, 0, fmt.Errorf("nonce: %w", err)
	}
	ct := aead.Seal(nil, nonce, plaintext, nil)
	return ct, nonce, c.kr.CurrentVersion(), nil
}

// Decrypt decrypts ciphertext using the key matching keyVer. Any tampering or
// mismatch surfaces as ErrTampered (wrapped).
func (c *Cipher) Decrypt(ciphertext, iv []byte, keyVer int16) ([]byte, error) {
	key, err := c.kr.KeyForVersion(keyVer)
	if err != nil {
		return nil, err
	}
	if len(iv) != NonceSize {
		return nil, fmt.Errorf("invalid IV length %d (want %d)", len(iv), NonceSize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	pt, err := aead.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTampered, err)
	}
	return pt, nil
}
