package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// AES256GCM supports AES256GCM
type AES256GCM struct {
	Algorithm
	aead cipher.AEAD
}

// NewAES creates a new AES value
func NewAES(key string) (*AES256GCM, error) {
	return NewAES256(key)
}

// NewAES256 creates a new AES256 value
func NewAES256(key string) (*AES256GCM, error) {
	return NewAES256GCM(key)
}

// NewAES256GCM creates instance of AES256GCM with passed key
func NewAES256GCM(key string) (*AES256GCM, error) {
	if len(key) != 32 {
		return nil, errors.New("key length MUST be 32 bytes for AES256")
	}

	aesCipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, err
	}

	return &AES256GCM{
		aead: aesGCM,
	}, nil
}

// Encrypt encrypts data with key
func (e *AES256GCM) Encrypt(plain []byte) ([]byte, error) {
	nonce := make([]byte, e.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return e.aead.Seal(nonce, nonce, plain, nil), nil
}

// Decrypt decrypts data with key
func (e *AES256GCM) Decrypt(crypted []byte) ([]byte, error) {
	nonceSize := e.aead.NonceSize()
	if len(crypted) < nonceSize {
		return nil, errors.New("encrypted data is not valid")
	}

	nonce, crypted := crypted[:nonceSize], crypted[nonceSize:]
	return e.aead.Open(nil, nonce, crypted, nil)
}
