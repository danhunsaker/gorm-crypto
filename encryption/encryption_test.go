package encryption_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"reflect"
	"sort"
	"testing"

	"github.com/danhunsaker/gorm-crypto/encryption"
	"golang.org/x/crypto/nacl/box"
)

func TestEncryption(t *testing.T) {
	for _, crypto := range getAlgos() {
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

func TestExports(t *testing.T) {
	for _, crypto := range getAlgos() {
		t.Run(reflect.TypeOf(crypto).String(), func(t *testing.T) {
			name, config := crypto.Name(), crypto.Config()
			created := encryption.FromYaml(name, config)

			if !reflect.DeepEqual(crypto, created) {
				t.Errorf("Expected %v; got %v instead", crypto, created)
			}
			if created.Name() != name {
				t.Errorf("Expected %v; got %v instead", name, created.Name())
			}
			if !reflect.DeepEqual(created.Config(), config) {
				t.Errorf("Expected %v; got %v instead", config, created.Config())
			}
		})
	}
}

func TestAlgoSupportFuncs(t *testing.T) {
	expected := append(encryption.SupportedAlgos(), "test")
	sort.Slice(expected, func(i, j int) bool {
		return expected[i] < expected[j]
	})

	encryption.RegisterAlgo("test", func(m map[string]interface{}) encryption.Algorithm {
		return nil
	})

	actual := encryption.SupportedAlgos()
	sort.Slice(actual, func(i, j int) bool {
		return actual[i] < actual[j]
	})

	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("Expected %v; got %v instead", expected, actual)
	}
}

func getAlgos() []encryption.Algorithm {
	naclPriv, naclPub, _ := box.GenerateKey(rand.Reader)
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)

	singleKey := make([]byte, 32)
	rand.Read(singleKey)

	return []encryption.Algorithm{
		suppressError(encryption.NewAES(string(singleKey))),
		suppressError(encryption.NewAES256(string(singleKey))),
		suppressError(encryption.NewAES256CBC(string(singleKey))),
		suppressError(encryption.NewAES256GCM(string(singleKey))),
		suppressError(encryption.NewChaCha20Poly1305(string(singleKey))),
		encryption.NewNaClBox(naclPriv, naclPub),
		encryption.NewRSA(rsaPriv),
		suppressError(encryption.NewXChaCha20Poly1305(string(singleKey))),
	}
}

func suppressError(in encryption.Algorithm, _ error) encryption.Algorithm {
	return in
}
