package gorm_crypto

import (
	"database/sql/driver"
	"errors"

	"github.com/danhunsaker/gorm-crypto/encoding"
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
	Encoder          encoding.Algorithm
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
		var binary, decrypted []byte

		binary, err = setup.Encoder.Decode(source)
		if err != nil {
			continue
		}

		decrypted, err = setup.EncryptAlgorithm.Decrypt(binary)
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

	encoded, err := config.Setups[0].Encoder.Encode(crypted)
	if err != nil {
		return nil, err
	}

	return encoded, nil
}

func verify(source []byte, dest interface{}) (bool, error) {
	var valid bool
	var err error

	for _, setup := range config.Setups {
		var signed internalStruct
		var signature []byte

		err = setup.Serializer.Unserialize(source, &signed)
		if err != nil {
			continue
		}

		signature, err = setup.Encoder.Decode(signed.Signature)
		if err != nil {
			continue
		}

		valid, err = setup.SignAlgorithm.Verify(signed.Raw, signature)
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

	signature, err := config.Setups[0].SignAlgorithm.Sign(serial)
	if err != nil {
		return nil, err
	}

	encoded, err := config.Setups[0].Encoder.Encode(signature)
	if err != nil {
		return nil, err
	}

	signed, err := config.Setups[0].Serializer.Serialize(internalStruct{Raw: serial, Signature: encoded})
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
		var decoded, decrypted, signature []byte

		err = setup.Serializer.Unserialize(source, &signed)
		if err != nil {
			continue
		}

		decoded, err = setup.Encoder.Decode(signed.Raw)
		if err != nil {
			continue
		}

		decrypted, err = setup.EncryptAlgorithm.Decrypt(decoded)
		if err != nil {
			continue
		}

		signature, err = setup.Encoder.Decode(signed.Signature)
		if err != nil {
			continue
		}

		valid, err = setup.SignAlgorithm.Verify(decrypted, signature)
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

	encodedData, err := config.Setups[0].Encoder.Encode(crypted)
	if err != nil {
		return nil, err
	}

	signature, err := config.Setups[0].SignAlgorithm.Sign(serial)
	if err != nil {
		return nil, err
	}

	encodedSign, err := config.Setups[0].Encoder.Encode(signature)
	if err != nil {
		return nil, err
	}

	signed, err := config.Setups[0].Serializer.Serialize(internalStruct{Raw: encodedData, Signature: encodedSign})
	if err != nil {
		return nil, err
	}

	return signed, nil
}
