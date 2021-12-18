package encryption

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
)

type RSA struct {
	Algorithm
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

func NewRSA(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) *RSA {
	return &RSA{
		privateKey: privateKey,
		publicKey:  publicKey,
	}
}

// Encrypt encrypts data with public key
func (e *RSA) Encrypt(plain []byte) ([]byte, error) {
	hash := sha512.New()
	crypted, err := rsa.EncryptOAEP(hash, rand.Reader, e.publicKey, plain, nil)
	if err != nil {
		return nil, err
	}
	return crypted, nil
}

// Decrypt decrypts data with private key
func (e *RSA) Decrypt(crypted []byte) ([]byte, error) {
	hash := sha512.New()
	plain, err := rsa.DecryptOAEP(hash, rand.Reader, e.privateKey, crypted, nil)
	if err != nil {
		return nil, err
	}
	return plain, nil
}
