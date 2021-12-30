package gc_test

import (
	"bytes"
	"database/sql/driver"
	"encoding/binary"
	"os"
	"testing"

	gc "github.com/danhunsaker/gorm-crypto"
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
	f := gc.Field{}

	if dataType := f.GormDataType(); dataType != "blob" {
		t.Errorf(`Expected data type "blob"; got "%s"`, dataType)
	}
}

func TestGormDBDataType(t *testing.T) {
	f := gc.Field{}
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

	aes, err := encryption.NewAES256GCM(eKey)
	if err != nil {
		panic(err)
	}

	gc.Init(gc.Config{
		Setups: []gc.Setup{
			{
				Encoder:          encoding.Base64{},
				Serializer:       serializing.JSON{},
				EncryptAlgorithm: aes,
				SignAlgorithm:    signing.NewED25519FromSeed(sKey),
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

	serializing.JSON{}.Unserialize(signed.([]byte), &unserial)

	unserial.Raw = attack

	reserial, _ := serializing.JSON{}.Serialize(unserial)

	return reserial
}

func rawValue(in interface{}) []byte {
	serial, _ := serializing.JSON{}.Serialize(in)

	return serial
}

func rawComplexValue(in interface{}) []byte {
	var bin bytes.Buffer
	binary.Write(&bin, binary.LittleEndian, in)
	serial, _ := serializing.JSON{}.Serialize(bin.Bytes())

	return serial
}

func suppressError(in driver.Value, ignore error) []byte {
	return in.([]byte)
}
