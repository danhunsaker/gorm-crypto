// Package gormcrypto is another library for encrypting/signing data with GORM
package gormcrypto

import (
	"database/sql/driver"
	"errors"
	"sort"
	"time"

	"github.com/danhunsaker/gorm-crypto/encoding"
	"github.com/danhunsaker/gorm-crypto/encryption"
	"github.com/danhunsaker/gorm-crypto/serializing"
	"github.com/danhunsaker/gorm-crypto/signing"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

// Config provides the global configuration data for gormcrypto.
// At the moment, that's just a list of different Setups your application supports.
// We support multiple Setups because application requirements change over time,
// and you'll want to be able to use values encrypted/signed by older keys/algorithms.
// The Time value used in the map indicates when the Setup was - or should be - made active in your code.
type Config struct {
	Setups map[time.Time]Setup
}

// Setup describes the way your data should be handled by gormcrypto.
// That includes the encryption algorithm/keys, the signing algorithm/keys,
// the mechanism for serializing values, and the encoding to use to coerce binary data into values that can safely be serialized/stored.
type Setup struct {
	Encoder          encoding.Algorithm
	Serializer       serializing.Algorithm
	EncryptAlgorithm encryption.Algorithm
	SignAlgorithm    signing.Algorithm
}

// Field defines some common features of every supported type, specifically those which are implemented the same way on every type.
type Field struct{}

// Init sets up gormcrypto for use by telling it which Config to use.
// NOTE: This function may be deprecated at some point if I can work out how to properly make gormcrypto into a GORM plugin.
func Init(c Config) error {
	if len(c.Setups) < 1 {
		return errors.New("database cryptography configuration incomplete")
	}
	config = c

	return nil
}

// CurrentSetup returns the most recent Setup value based on the Time it was set up under
func (c *Config) CurrentSetup() Setup {
	return c.UsedSetup(time.Now())
}

// UsedSetup returns the most recent Setup value based on the passed Time, falling back to CurrentSetup
func (c *Config) UsedSetup(at time.Time) Setup {
	keys := make([]time.Time, 0, len(c.Setups))
	for t := range c.Setups {
		keys = append(keys, t)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].Before(keys[j])
	})
	for _, t := range keys {
		if at.After(t) {
			return c.Setups[t]
		}
	}

	return c.Setups[keys[len(keys)-1]]
}

// GormDataType indicates the default type hint for GORM to use in migrations
func (Field) GormDataType() string {
	return "blob"
}

// GormDBDataType indicates the actual type hint for GORM to use in migrations, based on the connected server dialect
func (Field) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	switch db.Dialector.Name() {
	case "bigquery":
		return "BYTES"
	case "clickhouse":
		return "String"
	case "mysql":
		return "BLOB"
	case "postgres":
		return "BYTEA"
	case "sqlite":
		return "BLOB"
	case "sqlserver":
		return "varbinary(max)"
	}
	return ""
}

// PRIVATE

type internalStruct struct {
	Raw       []byte
	Signature []byte
	At        time.Time
}

var config Config

func decrypt(source []byte, dest interface{}) error {
	var err error
	var binary, decrypted []byte
	var in internalStruct

	for _, setup := range config.Setups {
		err = setup.Serializer.Unserialize(source, &in)
		if err != nil {
			break
		}
	}
	if err != nil {
		return err
	}
	setup := config.UsedSetup(in.At)

	binary, err = setup.Encoder.Decode(in.Raw)
	if err != nil {
		return err
	}

	decrypted, err = setup.EncryptAlgorithm.Decrypt(binary)
	if err != nil {
		return err
	}

	err = setup.Serializer.Unserialize(decrypted, &dest)
	if err == nil {
		return err
	}

	return nil
}

func encrypt(value interface{}) (driver.Value, error) {
	setup := config.CurrentSetup()
	out := internalStruct{At: time.Now()}

	serial, err := setup.Serializer.Serialize(value)
	if err != nil {
		return nil, err
	}

	crypted, err := setup.EncryptAlgorithm.Encrypt(serial)
	if err != nil {
		return nil, err
	}

	out.Raw, err = setup.Encoder.Encode(crypted)
	if err != nil {
		return nil, err
	}

	result, err := setup.Serializer.Serialize(out)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func verify(source []byte, dest interface{}) (bool, error) {
	var signed internalStruct
	var signature []byte
	var valid bool
	var err error

	for _, setup := range config.Setups {
		err = setup.Serializer.Unserialize(source, &signed)
		if err == nil {
			break
		}
	}
	if err != nil {
		return false, err
	}
	setup := config.UsedSetup(signed.At)

	signature, err = setup.Encoder.Decode(signed.Signature)
	if err != nil {
		return false, err
	}

	valid, err = setup.SignAlgorithm.Verify(signed.Raw, signature)
	if err != nil {
		return false, err
	}

	err = setup.Serializer.Unserialize(signed.Raw, &dest)
	if err != nil {
		return false, err
	}

	return valid, nil
}

func sign(value interface{}) (driver.Value, error) {
	setup := config.CurrentSetup()

	serial, err := setup.Serializer.Serialize(value)
	if err != nil {
		return nil, err
	}

	signature, err := setup.SignAlgorithm.Sign(serial)
	if err != nil {
		return nil, err
	}

	encoded, err := setup.Encoder.Encode(signature)
	if err != nil {
		return nil, err
	}

	signed, err := setup.Serializer.Serialize(internalStruct{Raw: serial, Signature: encoded, At: time.Now()})
	if err != nil {
		return nil, err
	}

	return signed, nil
}

func decryptVerify(source []byte, dest interface{}) (bool, error) {
	var signed internalStruct
	var decoded, decrypted, signature []byte
	var valid bool
	var err error

	for _, setup := range config.Setups {
		err = setup.Serializer.Unserialize(source, &signed)
		if err != nil {
			break
		}
	}
	if err != nil {
		return false, err
	}
	setup := config.UsedSetup(signed.At)

	decoded, err = setup.Encoder.Decode(signed.Raw)
	if err != nil {
		return false, err
	}

	decrypted, err = setup.EncryptAlgorithm.Decrypt(decoded)
	if err != nil {
		return false, err
	}

	signature, err = setup.Encoder.Decode(signed.Signature)
	if err != nil {
		return false, err
	}

	valid, err = setup.SignAlgorithm.Verify(decrypted, signature)
	if err != nil {
		return false, err
	}

	err = setup.Serializer.Unserialize(decrypted, &dest)
	if err != nil {
		return false, err
	}

	return valid, nil
}

func encryptSign(value interface{}) (driver.Value, error) {
	setup := config.CurrentSetup()

	serial, err := setup.Serializer.Serialize(value)
	if err != nil {
		return nil, err
	}

	crypted, err := setup.EncryptAlgorithm.Encrypt(serial)
	if err != nil {
		return nil, err
	}

	encodedData, err := setup.Encoder.Encode(crypted)
	if err != nil {
		return nil, err
	}

	signature, err := setup.SignAlgorithm.Sign(serial)
	if err != nil {
		return nil, err
	}

	encodedSign, err := setup.Encoder.Encode(signature)
	if err != nil {
		return nil, err
	}

	signed, err := setup.Serializer.Serialize(internalStruct{Raw: encodedData, Signature: encodedSign, At: time.Now()})
	if err != nil {
		return nil, err
	}

	return signed, nil
}
