package gorm_crypto

import (
	"database/sql/driver"

	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

type EncryptedAny struct {
	Raw interface{}
}

func (EncryptedAny) GormDataType() string {
	return baseType
}

func (EncryptedAny) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *EncryptedAny) Scan(value interface{}) error {
	return decrypt(value.([]byte), s.Raw)
}

func (s EncryptedAny) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

type NullEncryptedAny struct {
	Raw   interface{}
	Empty bool
}

func (NullEncryptedAny) GormDataType() string {
	return baseType
}

func (NullEncryptedAny) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullEncryptedAny) Scan(value interface{}) error {
	if value == nil {
		s.Raw = nil
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), s.Raw)
}

func (s NullEncryptedAny) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encrypt(s.Raw)
	}
}

type SignedAny struct {
	Raw   interface{}
	Valid bool
}

func (SignedAny) GormDataType() string {
	return baseType
}

func (SignedAny) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *SignedAny) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s SignedAny) Value() (driver.Value, error) {
	return sign(s.Raw)
}

type NullSignedAny struct {
	Raw   interface{}
	Empty bool
	Valid bool
}

func (NullSignedAny) GormDataType() string {
	return baseType
}

func (NullSignedAny) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullSignedAny) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = nil
		s.Empty = true
		s.Valid = false
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedAny) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return sign(s.Raw)
	}
}

type SignedEncryptedAny struct {
	Raw   interface{}
	Valid bool
}

func (SignedEncryptedAny) GormDataType() string {
	return baseType
}

func (SignedEncryptedAny) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *SignedEncryptedAny) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s SignedEncryptedAny) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

type NullSignedEncryptedAny struct {
	Raw   interface{}
	Empty bool
	Valid bool
}

func (NullSignedEncryptedAny) GormDataType() string {
	return baseType
}

func (NullSignedEncryptedAny) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullSignedEncryptedAny) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = nil
		s.Empty = true
		s.Valid = false
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedEncryptedAny) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encryptSign(s.Raw)
	}
}
