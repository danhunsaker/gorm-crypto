package encoding_test

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"reflect"
	"sort"
	"testing"

	"github.com/danhunsaker/gorm-crypto/encoding"
)

func TestEncoding(t *testing.T) {
	for _, encoder := range getAlgos() {
		t.Run(reflect.TypeOf(encoder).String(), func(t *testing.T) {
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
				t.Errorf("Expected %v; got %v instead", expected, actual)
			}
		})
	}
}

func TestExports(t *testing.T) {
	for _, crypto := range getAlgos() {
		t.Run(reflect.TypeOf(crypto).String(), func(t *testing.T) {
			name, config := crypto.Name(), crypto.Config()
			created := encoding.FromYaml(name, config)

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
	expected := append(encoding.SupportedAlgos(), "test")
	sort.Slice(expected, func(i, j int) bool {
		return expected[i] < expected[j]
	})

	encoding.RegisterAlgo("test", func(m map[string]interface{}) encoding.Algorithm {
		return nil
	})

	actual := encoding.SupportedAlgos()
	sort.Slice(actual, func(i, j int) bool {
		return actual[i] < actual[j]
	})

	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("Expected %v; got %v instead", expected, actual)
	}
}

func getAlgos() []encoding.Algorithm {
	return []encoding.Algorithm{
		encoding.ASCII85{},
		encoding.Base32{},
		encoding.Base64{},
		encoding.Hex{},
		encoding.PEM{},
	}
}
