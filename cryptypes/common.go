// Package cryptypes provides the supported cryptographic types supperted by gormcrypto out of the box
package cryptypes

import (
	"database/sql/driver"
	"time"

	gc "github.com/danhunsaker/gorm-crypto"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

// Field defines some common features of every supported type, specifically those which are implemented the same way on every type.
type Field struct{}

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

func encrypt(value interface{}) (driver.Value, error) {
	setup := gc.GlobalConfig().CurrentSetup()
	out := internalStruct{At: time.Now()}

	serial, err := setup.Serializer.Serialize(value)
	if err != nil {
		return nil, err
	}

	crypted, err := setup.Encrypter.Encrypt(serial)
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

func decrypt(source []byte, dest interface{}) error {
	var err error
	var binary, decrypted []byte
	var in internalStruct

	if len(source) < 1 {
		return nil
	}

	for _, setup := range gc.GlobalConfig().Setups {
		err = setup.Serializer.Unserialize(source, &in)
		if err == nil {
			break
		}
	}
	if err != nil {
		return err
	}
	setup := gc.GlobalConfig().UsedSetup(in.At)

	binary, err = setup.Encoder.Decode(in.Raw)
	if err != nil {
		return err
	}

	decrypted, err = setup.Encrypter.Decrypt(binary)
	if err != nil {
		return err
	}

	err = setup.Serializer.Unserialize(decrypted, &dest)
	if err != nil {
		return err
	}

	return nil
}

func sign(value interface{}) (driver.Value, error) {
	setup := gc.GlobalConfig().CurrentSetup()

	serial, err := setup.Serializer.Serialize(value)
	if err != nil {
		return nil, err
	}

	signature, err := setup.Signer.Sign(serial)
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

func verify(source []byte, dest interface{}) (bool, error) {
	var signed internalStruct
	var signature []byte
	var valid bool
	var err error

	if len(source) < 1 {
		return false, nil
	}

	for _, setup := range gc.GlobalConfig().Setups {
		err = setup.Serializer.Unserialize(source, &signed)
		if err == nil {
			break
		}
	}
	if err != nil {
		return false, err
	}
	setup := gc.GlobalConfig().UsedSetup(signed.At)

	signature, err = setup.Encoder.Decode(signed.Signature)
	if err != nil {
		return false, err
	}

	valid, err = setup.Signer.Verify(signed.Raw, signature)
	if err != nil {
		return false, err
	}

	err = setup.Serializer.Unserialize(signed.Raw, &dest)
	if err != nil {
		return false, err
	}

	return valid, nil
}

func encryptSign(value interface{}) (driver.Value, error) {
	setup := gc.GlobalConfig().CurrentSetup()

	serial, err := setup.Serializer.Serialize(value)
	if err != nil {
		return nil, err
	}

	crypted, err := setup.Encrypter.Encrypt(serial)
	if err != nil {
		return nil, err
	}

	encodedData, err := setup.Encoder.Encode(crypted)
	if err != nil {
		return nil, err
	}

	signature, err := setup.Signer.Sign(serial)
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

func decryptVerify(source []byte, dest interface{}) (bool, error) {
	var signed internalStruct
	var decoded, decrypted, signature []byte
	var valid bool
	var err error

	if len(source) < 1 {
		return false, nil
	}

	for _, setup := range gc.GlobalConfig().Setups {
		err = setup.Serializer.Unserialize(source, &signed)
		if err == nil {
			break
		}
	}
	if err != nil {
		return false, err
	}
	setup := gc.GlobalConfig().UsedSetup(signed.At)

	decoded, err = setup.Encoder.Decode(signed.Raw)
	if err != nil {
		return false, err
	}

	decrypted, err = setup.Encrypter.Decrypt(decoded)
	if err != nil {
		return false, err
	}

	signature, err = setup.Encoder.Decode(signed.Signature)
	if err != nil {
		return false, err
	}

	valid, err = setup.Signer.Verify(decrypted, signature)
	if err != nil {
		return false, err
	}

	err = setup.Serializer.Unserialize(decrypted, &dest)
	if err != nil {
		return false, err
	}

	return valid, nil
}
