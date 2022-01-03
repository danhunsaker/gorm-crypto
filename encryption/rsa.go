package encryption

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
)

func init() {
	RegisterAlgo("rsa", func(m map[string]interface{}) Algorithm {
		data, _ := hex.DecodeString(m["key"].(string))
		privKey, _ := x509.ParsePKCS1PrivateKey(data)
		algo := NewRSA(privKey)
		return algo
	})
}

// RSA supports RSA
type RSA struct {
	Algorithm
	privateKey *rsa.PrivateKey
}

// Name identifies the Algorithm as a string for exporting configurations
func (RSA) Name() string {
	return "rsa"
}

// Config converts an Algorthim's internal configuration into a map for export
func (e RSA) Config() map[string]interface{} {
	return map[string]interface{}{
		"key": hex.EncodeToString(x509.MarshalPKCS1PrivateKey(e.privateKey)),
	}
}

// NewRSA creates a new RSA value
func NewRSA(privateKey *rsa.PrivateKey) *RSA {
	return &RSA{
		privateKey: privateKey,
	}
}

// Encrypt encrypts data with public key
func (e *RSA) Encrypt(plain []byte) ([]byte, error) {
	hash := sha512.New()
	crypted, err := rsa.EncryptOAEP(hash, rand.Reader, &e.privateKey.PublicKey, plain, nil)
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
