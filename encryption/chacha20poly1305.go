package encryption

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

func init() {
	RegisterAlgo("chacha20", func(m map[string]interface{}) Algorithm {
		key, _ := hex.DecodeString(m["key"].(string))
		algo, _ := NewChaCha20Poly1305(string(key))
		return algo
	})
}

// ChaCha20Poly1305 supports ChaCha20Poly1305 encryption of arbitrary data
type ChaCha20Poly1305 struct {
	Algorithm
	key  string
	aead cipher.AEAD
}

// Name identifies the Algorithm as a string for exporting configurations
func (ChaCha20Poly1305) Name() string {
	return "chacha20"
}

// Config converts an Algorthim's internal configuration into a map for export
func (e ChaCha20Poly1305) Config() map[string]interface{} {
	return map[string]interface{}{
		"key": hex.EncodeToString([]byte(e.key)),
	}
}

// NewChaCha20Poly1305 creates instance of ChaCha20Poly1305 with passed key
func NewChaCha20Poly1305(key string) (*ChaCha20Poly1305, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, errors.New("key length MUST be 32 bytes for ChaCha20Poly1305")
	}

	ccpGCM, err := chacha20poly1305.New([]byte(key))
	if err != nil {
		return nil, err
	}

	return &ChaCha20Poly1305{
		key:  key,
		aead: ccpGCM,
	}, nil
}

// Encrypt encrypts data with key
func (e *ChaCha20Poly1305) Encrypt(plain []byte) ([]byte, error) {
	nonce := make([]byte, e.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return e.aead.Seal(nonce, nonce, plain, nil), nil
}

// Decrypt decrypts data with key
func (e *ChaCha20Poly1305) Decrypt(crypted []byte) ([]byte, error) {
	nonceSize := e.aead.NonceSize()
	if len(crypted) < nonceSize {
		return nil, errors.New("encrypted data is not valid")
	}

	nonce, crypted := crypted[:nonceSize], crypted[nonceSize:]
	return e.aead.Open(nil, nonce, crypted, nil)
}
