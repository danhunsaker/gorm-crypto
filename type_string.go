package gorm_crypto

import (
	"database/sql/driver"

	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

type EncryptedString struct {
	Raw string
}

func (EncryptedString) GormDataType() string {
	return baseType
}

func (EncryptedString) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *EncryptedString) Scan(value interface{}) error {
	return decrypt(value.([]byte), s.Raw)
}

func (s EncryptedString) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

type NullEncryptedString struct {
	Raw   string
	Empty bool
}

func (NullEncryptedString) GormDataType() string {
	return baseType
}

func (NullEncryptedString) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullEncryptedString) Scan(value interface{}) error {
	if value == nil {
		s.Raw = ""
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), s.Raw)
}

func (s NullEncryptedString) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encrypt(s.Raw)
	}
}

type SignedString struct {
	Raw   string
	Valid bool
}

func (SignedString) GormDataType() string {
	return baseType
}

func (SignedString) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *SignedString) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s SignedString) Value() (driver.Value, error) {
	return sign(s.Raw)
}

type NullSignedString struct {
	Raw   string
	Empty bool
	Valid bool
}

func (NullSignedString) GormDataType() string {
	return baseType
}

func (NullSignedString) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullSignedString) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = ""
		s.Empty = true
		s.Valid = false
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedString) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return sign(s.Raw)
	}
}

type SignedEncryptedString struct {
	Raw   string
	Valid bool
}

func (SignedEncryptedString) GormDataType() string {
	return baseType
}

func (SignedEncryptedString) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *SignedEncryptedString) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s SignedEncryptedString) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

type NullSignedEncryptedString struct {
	Raw   string
	Empty bool
	Valid bool
}

func (NullSignedEncryptedString) GormDataType() string {
	return baseType
}

func (NullSignedEncryptedString) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullSignedEncryptedString) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = ""
		s.Empty = true
		s.Valid = false
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedEncryptedString) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encryptSign(s.Raw)
	}
}
