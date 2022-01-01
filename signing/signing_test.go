package signing_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"reflect"
	"testing"

	"github.com/danhunsaker/gorm-crypto/signing"
)

func TestSigning(t *testing.T) {
	ecdsaPriv, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ed25519Pub, ed25519Priv, _ := ed25519.GenerateKey(rand.Reader)

	singleKey := make([]byte, 32)
	rand.Read(singleKey)

	for _, signer := range []signing.Algorithm{
		signing.NewECDSA(ecdsaPriv, &ecdsaPriv.PublicKey),
		signing.NewED25519(&ed25519Priv, &ed25519Pub),
		signing.NewED25519FromSeed(string(singleKey)),
	} {
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
