package gorm_crypto

import (
	"database/sql/driver"

	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

type EncryptedUint struct {
	Raw uint
}

func (EncryptedUint) GormDataType() string {
	return baseType
}

func (EncryptedUint) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *EncryptedUint) Scan(value interface{}) error {
	return decrypt(value.([]byte), s.Raw)
}

func (s EncryptedUint) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

type NullEncryptedUint struct {
	Raw   uint
	Empty bool
}

func (NullEncryptedUint) GormDataType() string {
	return baseType
}

func (NullEncryptedUint) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullEncryptedUint) Scan(value interface{}) error {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), s.Raw)
}

func (s NullEncryptedUint) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encrypt(s.Raw)
	}
}

type SignedUint struct {
	Raw   uint
	Valid bool
}

func (SignedUint) GormDataType() string {
	return baseType
}

func (SignedUint) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *SignedUint) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s SignedUint) Value() (driver.Value, error) {
	return sign(s.Raw)
}

type NullSignedUint struct {
	Raw   uint
	Empty bool
	Valid bool
}

func (NullSignedUint) GormDataType() string {
	return baseType
}

func (NullSignedUint) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullSignedUint) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = false
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedUint) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return sign(s.Raw)
	}
}

type SignedEncryptedUint struct {
	Raw   uint
	Valid bool
}

func (SignedEncryptedUint) GormDataType() string {
	return baseType
}

func (SignedEncryptedUint) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *SignedEncryptedUint) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s SignedEncryptedUint) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

type NullSignedEncryptedUint struct {
	Raw   uint
	Empty bool
	Valid bool
}

func (NullSignedEncryptedUint) GormDataType() string {
	return baseType
}

func (NullSignedEncryptedUint) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullSignedEncryptedUint) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = false
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedEncryptedUint) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encryptSign(s.Raw)
	}
}
