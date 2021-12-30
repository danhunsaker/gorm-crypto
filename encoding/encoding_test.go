package encoding_test

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"reflect"
	"testing"

	"github.com/danhunsaker/gorm-crypto/encoding"
)

func TestEncoding(t *testing.T) {
	for _, encoder := range []encoding.Algorithm{
		encoding.ASCII85{},
		encoding.Base32{},
		encoding.Base64{},
		encoding.Hex{},
		encoding.PEM{},
	} {
		size, _ := rand.Int(rand.Reader, big.NewInt(64))
		expected := make([]byte, size.Int64())
		rand.Read(expected)

		encoded, err := encoder.Encode(expected)
		if err != nil {
			t.Error(err)
		}
		actual, err := encoder.Decode(encoded)
		if err != nil {
			t.Error(err)
		}

		if !bytes.Equal(actual, expected) {
			t.Errorf("%s: Expected %v; got %v instead", reflect.TypeOf(encoder).String(), expected, actual)
		}
	}
}
