package gormcrypto_test

import (
	"reflect"
	"sort"
	"testing"
	"time"

	gormcrypto "github.com/danhunsaker/gorm-crypto"
	"github.com/danhunsaker/gorm-crypto/encoding"
	"github.com/danhunsaker/gorm-crypto/encryption"
	"github.com/danhunsaker/gorm-crypto/serializing"
	"github.com/danhunsaker/gorm-crypto/signing"
)

func TestInitGlobalConfig(t *testing.T) {
	config := getTestConfig()

	if err := gormcrypto.Init(config); err != nil {
		t.Fatal(err)
	}
	global := gormcrypto.GlobalConfig()

	if !reflect.DeepEqual(global, config) {
		t.Errorf("Expected %v; got %v instead", config, global)
	}
}

func TestConfigExport(t *testing.T) {
	config := getTestConfig()

	yaml, err := config.ConfigToBytes()
	if err != nil {
		t.Fatal(err)
	}
	imported := gormcrypto.ConfigFromBytes(yaml)

	if !reflect.DeepEqual(imported, config) {
		t.Errorf("Expected %v; got %v instead", config, imported)
	}
}

func TestSetupSelection(t *testing.T) {
	config := getTestConfig()
	keys := make([]time.Time, 0, len(config.Setups))
	for t2 := range config.Setups {
		keys = append(keys, t2)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].After(keys[j])
	})

	current := config.CurrentSetup()
	if !reflect.DeepEqual(current, config.Setups[keys[0]]) {
		t.Errorf("Expected current == %v; got %v instead", config.Setups[keys[0]], current)
	}

	ago30Min := config.UsedSetup(time.Now().Add(-30 * time.Minute))
	if !reflect.DeepEqual(ago30Min, config.Setups[keys[1]]) {
		t.Errorf("Expected ago30Min == %v; got %v instead", config.Setups[keys[1]], ago30Min)
	}
	ago90Min := config.UsedSetup(time.Now().Add(-90 * time.Minute))
	if !reflect.DeepEqual(ago90Min, config.Setups[keys[2]]) {
		t.Errorf("Expected ago90Min == %v; got %v instead", config.Setups[keys[2]], ago90Min)
	}
	ago4Hr := config.UsedSetup(time.Now().Add(-4 * time.Hour))
	if !reflect.DeepEqual(ago4Hr, config.Setups[keys[0]]) {
		t.Errorf("Expected ago2Hr == %v; got %v instead", config.Setups[keys[0]], ago4Hr)
	}
}

func TestSetupToString(t *testing.T) {
	config := getTestConfig()
	setup := config.CurrentSetup()
	expected := "{encoding.Base64 serializing.JSON *encryption.XChaCha20Poly1305 *signing.ED25519}"

	if setup.String() != expected {
		t.Errorf("Expected %v; got %v instead", expected, setup.String())
	}
}

func getTestConfig() gormcrypto.Config {
	enc, _ := encryption.NewXChaCha20Poly1305("EncryptionKeyThatShouldBe32Bytes")
	sig := signing.NewED25519FromSeed("SigningKeyThatShouldBe32BytesToo")

	return gormcrypto.Config{
		Setups: map[time.Time]gormcrypto.Setup{
			time.Now().UTC(): {
				Encoder:    encoding.Base64{},
				Serializer: serializing.JSON{},
				Encrypter:  enc,
				Signer:     sig,
			},
			time.Now().Add(-1 * time.Hour).UTC(): {
				Encoder:    encoding.Hex{},
				Serializer: serializing.JSON{},
				Encrypter:  enc,
				Signer:     sig,
			},
			time.Now().Add(-2 * time.Hour).UTC(): {
				Encoder:    encoding.ASCII85{},
				Serializer: serializing.GOB{},
				Encrypter:  enc,
				Signer:     sig,
			},
		},
	}
}
