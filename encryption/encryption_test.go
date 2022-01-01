package encryption_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"reflect"
	"testing"

	"github.com/danhunsaker/gorm-crypto/encryption"
	"golang.org/x/crypto/nacl/box"
)

func TestEncryption(t *testing.T) {
	naclPriv, naclPub, _ := box.GenerateKey(rand.Reader)
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)

	singleKey := make([]byte, 32)
	rand.Read(singleKey)

	for _, crypto := range []encryption.Algorithm{
		suppressError(encryption.NewAES(string(singleKey))),
		suppressError(encryption.NewAES256(string(singleKey))),
		suppressError(encryption.NewAES256CBC(string(singleKey))),
		suppressError(encryption.NewAES256GCM(string(singleKey))),
		suppressError(encryption.NewChaCha20Poly1305(string(singleKey))),
		encryption.NewNaClBox(naclPriv, naclPub),
		encryption.NewRSA(rsaPriv, &rsaPriv.PublicKey),
		suppressError(encryption.NewXChaCha20Poly1305(string(singleKey))),
	} {
		t.Run(reflect.TypeOf(crypto).String(), func(t *testing.T) {
			size, _ := rand.Int(rand.Reader, big.NewInt(64))
			expected := make([]byte, size.Int64())
			rand.Read(expected)

			crypted, err := crypto.Encrypt(expected)
			if err != nil {
				t.Error(err)
			}
			actual, err := crypto.Decrypt(crypted)
			if err != nil {
				t.Error(err)
			}

			if !bytes.Equal(actual, expected) {
				t.Errorf("Expected %v; got %v instead", expected, actual)
			}
		})
	}
}

func suppressError(in encryption.Algorithm, _ error) encryption.Algorithm {
	return in
}
