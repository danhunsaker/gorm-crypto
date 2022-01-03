package signing_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"reflect"
	"sort"
	"testing"

	"github.com/danhunsaker/gorm-crypto/signing"
)

func TestSigning(t *testing.T) {
	for _, signer := range getAlgos() {
		t.Run(reflect.TypeOf(signer).String(), func(t *testing.T) {
			size, _ := rand.Int(rand.Reader, big.NewInt(64))
			expected := make([]byte, size.Int64())
			rand.Read(expected)

			signed, err := signer.Sign(expected)
			if err != nil {
				t.Error(err)
			}
			matches, err := signer.Verify(expected, signed)
			if err != nil {
				t.Error(err)
			}

			if !matches {
				t.Error("Signature did not verify")
			}
		})
	}
}

func TestExports(t *testing.T) {
	for _, crypto := range getAlgos() {
		t.Run(reflect.TypeOf(crypto).String(), func(t *testing.T) {
			name, config := crypto.Name(), crypto.Config()
			created := signing.FromYaml(name, config)

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
	expected := append(signing.SupportedAlgos(), "test")
	sort.Slice(expected, func(i, j int) bool {
		return expected[i] < expected[j]
	})

	signing.RegisterAlgo("test", func(m map[string]interface{}) signing.Algorithm {
		return nil
	})

	actual := signing.SupportedAlgos()
	sort.Slice(actual, func(i, j int) bool {
		return actual[i] < actual[j]
	})

	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("Expected %v; got %v instead", expected, actual)
	}
}

func getAlgos() []signing.Algorithm {
	ecdsaPriv, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ed25519Pub, ed25519Priv, _ := ed25519.GenerateKey(rand.Reader)

	singleKey := make([]byte, 32)
	rand.Read(singleKey)

	return []signing.Algorithm{
		signing.NewECDSA(ecdsaPriv, &ecdsaPriv.PublicKey),
		signing.NewED25519(&ed25519Priv, &ed25519Pub),
		signing.NewED25519FromSeed(string(singleKey)),
	}
}
