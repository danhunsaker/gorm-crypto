package gorm_crypto

import (
	"database/sql/driver"

	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

type EncryptedInt8 struct {
	Raw int8
}

func (EncryptedInt8) GormDataType() string {
	return baseType
}

func (EncryptedInt8) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *EncryptedInt8) Scan(value interface{}) error {
	return decrypt(value.([]byte), s.Raw)
}

func (s EncryptedInt8) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

type NullEncryptedInt8 struct {
	Raw   int8
	Empty bool
}

func (NullEncryptedInt8) GormDataType() string {
	return baseType
}

func (NullEncryptedInt8) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullEncryptedInt8) Scan(value interface{}) error {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), s.Raw)
}

func (s NullEncryptedInt8) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encrypt(s.Raw)
	}
}

type SignedInt8 struct {
	Raw   int8
	Valid bool
}

func (SignedInt8) GormDataType() string {
	return baseType
}

func (SignedInt8) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *SignedInt8) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s SignedInt8) Value() (driver.Value, error) {
	return sign(s.Raw)
}

type NullSignedInt8 struct {
	Raw   int8
	Empty bool
	Valid bool
}

func (NullSignedInt8) GormDataType() string {
	return baseType
}

func (NullSignedInt8) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullSignedInt8) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = false
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedInt8) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return sign(s.Raw)
	}
}

type SignedEncryptedInt8 struct {
	Raw   int8
	Valid bool
}

func (SignedEncryptedInt8) GormDataType() string {
	return baseType
}

func (SignedEncryptedInt8) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *SignedEncryptedInt8) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s SignedEncryptedInt8) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

type NullSignedEncryptedInt8 struct {
	Raw   int8
	Empty bool
	Valid bool
}

func (NullSignedEncryptedInt8) GormDataType() string {
	return baseType
}

func (NullSignedEncryptedInt8) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullSignedEncryptedInt8) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = false
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedEncryptedInt8) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encryptSign(s.Raw)
	}
}
