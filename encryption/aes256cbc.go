package encryption

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

type AES256CBC struct {
	Algorithm
	block cipher.Block
}

func NewAES256CBC(key string) (*AES256CBC, error) {
	if len(key) != 32 {
		return nil, errors.New("key length MUST be 32 bytes for AES256")
	}

	block, err := aes.NewCipher([]byte(key))

	if err != nil {
		return nil, err
	}

	return &AES256CBC{
		block: block,
	}, nil
}

// Encrypt encrypts data with key
func (e *AES256CBC) Encrypt(plain []byte) ([]byte, error) {
	if f := len(plain) % aes.BlockSize; f != 0 {
		padding := make([]byte, aes.BlockSize-f)
		plain = append(plain, padding...)
	}

	crypted := make([]byte, aes.BlockSize+len(plain))
	iv := crypted[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(e.block, iv)
	mode.CryptBlocks(crypted[aes.BlockSize:], plain)
	return crypted, nil
}

// Decrypt decrypts data with key
func (e *AES256CBC) Decrypt(crypted []byte) ([]byte, error) {
	if len(crypted) < aes.BlockSize {
		return nil, errors.New("encrypted data too short")
	}

	iv := crypted[:aes.BlockSize]
	crypted = crypted[aes.BlockSize:]

	if len(crypted)%aes.BlockSize != 0 {
		return nil, errors.New("encrypted data is not a multiple of the AES256 block size")
	}

	mode := cipher.NewCBCDecrypter(e.block, iv)
	mode.CryptBlocks(crypted, crypted)
	withoutPadding := bytes.ReplaceAll(crypted, make([]byte, 1), []byte{})
	return withoutPadding, nil
}
