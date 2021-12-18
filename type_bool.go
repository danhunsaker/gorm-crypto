package gorm_crypto

import (
	"database/sql/driver"

	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

type EncryptedBool struct {
	Raw bool
}

func (EncryptedBool) GormDataType() string {
	return baseType
}

func (EncryptedBool) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *EncryptedBool) Scan(value interface{}) error {
	return decrypt(value.([]byte), s.Raw)
}

func (s EncryptedBool) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

type NullEncryptedBool struct {
	Raw   bool
	Empty bool
}

func (NullEncryptedBool) GormDataType() string {
	return baseType
}

func (NullEncryptedBool) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullEncryptedBool) Scan(value interface{}) error {
	if value == nil {
		s.Raw = false
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), s.Raw)
}

func (s NullEncryptedBool) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encrypt(s.Raw)
	}
}

type SignedBool struct {
	Raw   bool
	Valid bool
}

func (SignedBool) GormDataType() string {
	return baseType
}

func (SignedBool) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *SignedBool) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s SignedBool) Value() (driver.Value, error) {
	return sign(s.Raw)
}

type NullSignedBool struct {
	Raw   bool
	Empty bool
	Valid bool
}

func (NullSignedBool) GormDataType() string {
	return baseType
}

func (NullSignedBool) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullSignedBool) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = false
		s.Empty = true
		s.Valid = false
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedBool) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return sign(s.Raw)
	}
}

type SignedEncryptedBool struct {
	Raw   bool
	Valid bool
}

func (SignedEncryptedBool) GormDataType() string {
	return baseType
}

func (SignedEncryptedBool) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *SignedEncryptedBool) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s SignedEncryptedBool) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

type NullSignedEncryptedBool struct {
	Raw   bool
	Empty bool
	Valid bool
}

func (NullSignedEncryptedBool) GormDataType() string {
	return baseType
}

func (NullSignedEncryptedBool) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullSignedEncryptedBool) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = false
		s.Empty = true
		s.Valid = false
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedEncryptedBool) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encryptSign(s.Raw)
	}
}
