// Package cryptypes_test houses the tests for the various types defined by the gormcrypto package
package cryptypes_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"database/sql/driver"
	"encoding/binary"
	"os"
	"testing"
	"time"

	gc "github.com/danhunsaker/gorm-crypto"
	"github.com/danhunsaker/gorm-crypto/cryptypes"
	"github.com/danhunsaker/gorm-crypto/encoding"
	"github.com/danhunsaker/gorm-crypto/encryption"
	"github.com/danhunsaker/gorm-crypto/serializing"
	"github.com/danhunsaker/gorm-crypto/signing"
	"gorm.io/driver/bigquery"
	"gorm.io/driver/clickhouse"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/driver/sqlserver"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

func TestGormDataType(t *testing.T) {
	f := cryptypes.Field{}

	if dataType := f.GormDataType(); dataType != "blob" {
		t.Errorf(`Expected data type "blob"; got "%s"`, dataType)
	}
}

func TestGormDBDataType(t *testing.T) {
	f := cryptypes.Field{}
	testDialectors := map[gorm.Dialector]string{
		bigquery.Dialector{}:   "BYTES",
		clickhouse.Dialector{}: "String",
		mysql.Dialector{}:      "BLOB",
		postgres.Dialector{}:   "BYTEA",
		sqlite.Dialector{}:     "BLOB",
		sqlserver.Dialector{}:  "varbinary(max)",
	}

	for dialector, expected := range testDialectors {
		testGorm := gorm.DB{Config: &gorm.Config{Dialector: dialector}}

		if actual := f.GormDBDataType(&testGorm, &schema.Field{}); actual != expected {
			t.Errorf(`Expected data type "%s"; got "%s"`, expected, actual)
		}
	}
}

func TestMain(m *testing.M) {
	var eKey = "EncryptionKeyThatShouldBe32Bytes"
	var sKey = "SigningKeyThatShouldBe32BytesToo"

	xchacha, err := encryption.NewXChaCha20Poly1305(eKey)
	if err != nil {
		panic(err)
	}

	aes, err := encryption.NewAES256GCM(eKey)
	if err != nil {
		panic(err)
	}

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		panic(err)
	}

	gc.Init(gc.Config{
		Setups: map[time.Time]gc.Setup{
			time.Now().Add(-1 * time.Minute): {
				Encoder:          encoding.Base64{},
				Serializer:       serializing.JSON{},
				EncryptAlgorithm: xchacha,
				SignAlgorithm:    signing.NewED25519FromSeed(sKey),
			},
			time.Now().Add(1 * time.Hour): {
				Encoder:          encoding.Hex{},
				Serializer:       serializing.GOB{},
				EncryptAlgorithm: aes,
				SignAlgorithm:    signing.NewECDSA(ecdsaKey, &ecdsaKey.PublicKey),
			},
			time.Now().Add(-1 * time.Hour): {
				Encoder:          encoding.Hex{},
				Serializer:       serializing.GOB{},
				EncryptAlgorithm: aes,
				SignAlgorithm:    signing.NewECDSA(ecdsaKey, &ecdsaKey.PublicKey),
			},
		},
	})

	result := m.Run()

	os.Exit(result)
}

// Internal Support

type internalStruct struct {
	Raw       []byte
	Signature []byte
	At        time.Time
}

type testStruct struct {
	Name   string
	Age    int
	Gender *rune
}

// Equals ::: Struct
func (actual testStruct) Equals(expected testStruct) bool {
	return actual.Name == expected.Name && actual.Age == expected.Age && *actual.Gender == *expected.Gender
}

func tamperWith(signed driver.Value, attack []byte) []byte {
	var unserial internalStruct

	gc.GlobalConfig().CurrentSetup().Serializer.Unserialize(signed.([]byte), &unserial)

	unserial.Raw = attack

	reserial, _ := gc.GlobalConfig().CurrentSetup().Serializer.Serialize(unserial)

	return reserial
}

func rawValue(in interface{}) []byte {
	serial, _ := gc.GlobalConfig().CurrentSetup().Serializer.Serialize(in)

	return serial
}

func rawComplexValue(in interface{}) []byte {
	var bin bytes.Buffer
	binary.Write(&bin, binary.LittleEndian, in)
	serial, _ := gc.GlobalConfig().CurrentSetup().Serializer.Serialize(bin.Bytes())

	return serial
}

func unwrapValue(in driver.Valuer) []byte {
	var out internalStruct
	wrapped := suppressError(in.Value())
	gc.GlobalConfig().CurrentSetup().Serializer.Unserialize(wrapped, &out)

	return out.Raw
}

func suppressError(in driver.Value, ignore error) []byte {
	return in.([]byte)
}
