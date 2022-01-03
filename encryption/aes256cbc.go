package encryption

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
)

func init() {
	RegisterAlgo("aes256cbc", func(m map[string]interface{}) Algorithm {
		key, _ := hex.DecodeString(m["key"].(string))
		algo, _ := NewAES256CBC(string(key))
		return algo
	})
}

// AES256CBC supports AES256CBC encryption of arbitrary data
type AES256CBC struct {
	Algorithm
	key   string
	block cipher.Block
}

// Name identifies the Algorithm as a string for exporting configurations
func (AES256CBC) Name() string {
	return "aes256cbc"
}

// Config converts an Algorthim's internal configuration into a map for export
func (e AES256CBC) Config() map[string]interface{} {
	return map[string]interface{}{
		"key": hex.EncodeToString([]byte(e.key)),
	}
}

// NewAES256CBC creates a new AES256CBC value
func NewAES256CBC(key string) (*AES256CBC, error) {
	if len(key) != 32 {
		return nil, errors.New("key length MUST be 32 bytes for AES256")
	}

	block, err := aes.NewCipher([]byte(key))

	if err != nil {
		return nil, err
	}

	return &AES256CBC{
		key:   key,
		block: block,
	}, nil
}

// Encrypt encrypts data with key
func (e *AES256CBC) Encrypt(plain []byte) ([]byte, error) {
	padded := 0

	if f := len(plain) % aes.BlockSize; f != 0 {
		padded = aes.BlockSize - f
		plain = append(plain, bytes.Repeat([]byte{byte(padded)}, padded)...)
	}

	crypted := make([]byte, aes.BlockSize+len(plain)+1)
	iv := crypted[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	crypted[aes.BlockSize] = byte(padded)

	mode := cipher.NewCBCEncrypter(e.block, iv)
	mode.CryptBlocks(crypted[aes.BlockSize+1:], plain)
	return crypted, nil
}

// Decrypt decrypts data with key
func (e *AES256CBC) Decrypt(crypted []byte) ([]byte, error) {
	if len(crypted) < aes.BlockSize {
		return nil, errors.New("encrypted data too short")
	}

	iv := crypted[:aes.BlockSize]
	padded := crypted[aes.BlockSize]
	crypted = crypted[aes.BlockSize+1:]

	if len(crypted)%aes.BlockSize != 0 {
		return nil, errors.New("encrypted data is not a multiple of the AES256 block size")
	}

	mode := cipher.NewCBCDecrypter(e.block, iv)
	decrypted := make([]byte, len(crypted))
	mode.CryptBlocks(decrypted, crypted)

	if int(padded) > 0 {
		suffix := bytes.Repeat([]byte{padded}, int(padded))
		return bytes.TrimSuffix(decrypted, suffix), nil
	}

	return decrypted, nil
}
