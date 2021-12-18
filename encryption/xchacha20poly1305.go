package encryption

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

type XChaCha20Poly1305 struct {
	Algorithm
	aead cipher.AEAD
}

// NewXChaCha20Poly1305 creates instance of XChaCha20Poly1305 with passed key
func NewXChaCha20Poly1305(key string) (*XChaCha20Poly1305, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, errors.New("key length MUST be 32 bytes for XChaCha20Poly1305")
	}

	ccpGCM, err := chacha20poly1305.NewX([]byte(key))
	if err != nil {
		return nil, err
	}

	return &XChaCha20Poly1305{
		aead: ccpGCM,
	}, nil
}

// Encrypt encrypts data with key
func (e *XChaCha20Poly1305) Encrypt(plain []byte) ([]byte, error) {
	nonce := make([]byte, e.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return e.aead.Seal(nonce, nonce, plain, nil), nil
}

// Decrypt decrypts data with key
func (e *XChaCha20Poly1305) Decrypt(crypted []byte) ([]byte, error) {
	nonceSize := e.aead.NonceSize()
	if len(crypted) < nonceSize {
		return nil, errors.New("encrypted data is not valid")
	}

	nonce, crypted := crypted[:nonceSize], crypted[nonceSize:]
	return e.aead.Open(nil, nonce, crypted, nil)
}
