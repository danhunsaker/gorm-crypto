package gorm_crypto

import (
	"database/sql/driver"

	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

type EncryptedByteSlice struct {
	Raw []byte
}

func (EncryptedByteSlice) GormDataType() string {
	return baseType
}

func (EncryptedByteSlice) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *EncryptedByteSlice) Scan(value interface{}) error {
	return decrypt(value.([]byte), s.Raw)
}

func (s EncryptedByteSlice) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

type NullEncryptedByteSlice struct {
	Raw   []byte
	Empty bool
}

func (NullEncryptedByteSlice) GormDataType() string {
	return baseType
}

func (NullEncryptedByteSlice) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullEncryptedByteSlice) Scan(value interface{}) error {
	if value == nil {
		s.Raw = []byte{}
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), s.Raw)
}

func (s NullEncryptedByteSlice) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encrypt(s.Raw)
	}
}

type SignedByteSlice struct {
	Raw   []byte
	Valid bool
}

func (SignedByteSlice) GormDataType() string {
	return baseType
}

func (SignedByteSlice) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *SignedByteSlice) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s SignedByteSlice) Value() (driver.Value, error) {
	return sign(s.Raw)
}

type NullSignedByteSlice struct {
	Raw   []byte
	Empty bool
	Valid bool
}

func (NullSignedByteSlice) GormDataType() string {
	return baseType
}

func (NullSignedByteSlice) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullSignedByteSlice) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = []byte{}
		s.Empty = true
		s.Valid = false
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedByteSlice) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return sign(s.Raw)
	}
}

type SignedEncryptedByteSlice struct {
	Raw   []byte
	Valid bool
}

func (SignedEncryptedByteSlice) GormDataType() string {
	return baseType
}

func (SignedEncryptedByteSlice) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *SignedEncryptedByteSlice) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s SignedEncryptedByteSlice) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

type NullSignedEncryptedByteSlice struct {
	Raw   []byte
	Empty bool
	Valid bool
}

func (NullSignedEncryptedByteSlice) GormDataType() string {
	return baseType
}

func (NullSignedEncryptedByteSlice) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullSignedEncryptedByteSlice) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = []byte{}
		s.Empty = true
		s.Valid = false
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedEncryptedByteSlice) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encryptSign(s.Raw)
	}
}
