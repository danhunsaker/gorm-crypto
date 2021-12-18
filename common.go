package gorm_crypto

import (
	"database/sql/driver"
	"errors"

	"github.com/danhunsaker/gorm-crypto/encryption"
	"github.com/danhunsaker/gorm-crypto/serializing"
	"github.com/danhunsaker/gorm-crypto/signing"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

type Config struct {
	Setups []Setup
}

var config Config

type Setup struct {
	Serializer       serializing.Algorithm
	EncryptAlgorithm encryption.Algorithm
	SignAlgorithm    signing.Algorithm
}

func Init(c Config) error {
	if len(c.Setups) < 1 {
		return errors.New("database cryptography configuration incomplete")
	}
	config = c

	return nil
}

// PRIVATE

const baseType = "blob"

type internalStruct struct {
	Raw       []byte
	Signature []byte
}

func serverType(db *gorm.DB, field *schema.Field) string {
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

func decrypt(source []byte, dest interface{}) error {
	var err error

	for _, setup := range config.Setups {
		var decrypted []byte

		decrypted, err = setup.EncryptAlgorithm.Decrypt(source)
		if err != nil {
			continue
		}

		err = setup.Serializer.Unserialize(decrypted, &dest)
		if err == nil {
			break
		}
	}
	if err != nil {
		return err
	}

	return nil
}

func encrypt(value interface{}) (driver.Value, error) {
	serial, err := config.Setups[0].Serializer.Serialize(value)
	if err != nil {
		return nil, err
	}

	crypted, err := config.Setups[0].EncryptAlgorithm.Encrypt(serial)
	if err != nil {
		return nil, err
	}

	return crypted, nil
}

func verify(source []byte, dest interface{}) (bool, error) {
	var valid bool
	var err error

	for _, setup := range config.Setups {
		var signed internalStruct

		err = setup.Serializer.Unserialize(source, &signed)
		if err != nil {
			continue
		}

		valid, err = setup.SignAlgorithm.Verify(signed.Raw, signed.Signature)
		if err != nil {
			continue
		}

		err = setup.Serializer.Unserialize(signed.Raw, &dest)
		if err == nil {
			break
		}
	}
	if err != nil {
		return false, err
	}

	return valid, nil
}

func sign(value interface{}) (driver.Value, error) {
	serial, err := config.Setups[0].Serializer.Serialize(value)
	if err != nil {
		return nil, err
	}

	sigature, err := config.Setups[0].SignAlgorithm.Sign(serial)
	if err != nil {
		return nil, err
	}

	signed, err := config.Setups[0].Serializer.Serialize(internalStruct{Raw: serial, Signature: sigature})
	if err != nil {
		return nil, err
	}

	return signed, nil
}

func decryptVerify(source []byte, dest interface{}) (bool, error) {
	var valid bool
	var err error

	for _, setup := range config.Setups {
		var signed internalStruct
		var decrypted []byte

		err = setup.Serializer.Unserialize(source, &signed)
		if err != nil {
			continue
		}

		decrypted, err = setup.EncryptAlgorithm.Decrypt(signed.Raw)
		if err != nil {
			continue
		}

		valid, err = setup.SignAlgorithm.Verify(decrypted, signed.Signature)
		if err != nil {
			continue
		}

		err = setup.Serializer.Unserialize(decrypted, &dest)
		if err == nil {
			break
		}
	}
	if err != nil {
		return false, err
	}

	return valid, nil
}

func encryptSign(value interface{}) (driver.Value, error) {
	serial, err := config.Setups[0].Serializer.Serialize(value)
	if err != nil {
		return nil, err
	}

	crypted, err := config.Setups[0].EncryptAlgorithm.Encrypt(serial)
	if err != nil {
		return nil, err
	}

	sigature, err := config.Setups[0].SignAlgorithm.Sign(serial)
	if err != nil {
		return nil, err
	}

	signed, err := config.Setups[0].Serializer.Serialize(internalStruct{Raw: crypted, Signature: sigature})
	if err != nil {
		return nil, err
	}

	return signed, nil
}
