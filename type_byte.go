package gorm_crypto

import (
	"database/sql/driver"

	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

type EncryptedByte struct {
	Raw byte
}

func (EncryptedByte) GormDataType() string {
	return baseType
}

func (EncryptedByte) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *EncryptedByte) Scan(value interface{}) error {
	return decrypt(value.([]byte), s.Raw)
}

func (s EncryptedByte) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

type NullEncryptedByte struct {
	Raw   byte
	Empty bool
}

func (NullEncryptedByte) GormDataType() string {
	return baseType
}

func (NullEncryptedByte) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullEncryptedByte) Scan(value interface{}) error {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), s.Raw)
}

func (s NullEncryptedByte) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encrypt(s.Raw)
	}
}

type SignedByte struct {
	Raw   byte
	Valid bool
}

func (SignedByte) GormDataType() string {
	return baseType
}

func (SignedByte) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *SignedByte) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s SignedByte) Value() (driver.Value, error) {
	return sign(s.Raw)
}

type NullSignedByte struct {
	Raw   byte
	Empty bool
	Valid bool
}

func (NullSignedByte) GormDataType() string {
	return baseType
}

func (NullSignedByte) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullSignedByte) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = false
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedByte) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return sign(s.Raw)
	}
}

type SignedEncryptedByte struct {
	Raw   byte
	Valid bool
}

func (SignedEncryptedByte) GormDataType() string {
	return baseType
}

func (SignedEncryptedByte) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *SignedEncryptedByte) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s SignedEncryptedByte) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

type NullSignedEncryptedByte struct {
	Raw   byte
	Empty bool
	Valid bool
}

func (NullSignedEncryptedByte) GormDataType() string {
	return baseType
}

func (NullSignedEncryptedByte) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullSignedEncryptedByte) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = false
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedEncryptedByte) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encryptSign(s.Raw)
	}
}
