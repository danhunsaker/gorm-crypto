package gorm_crypto

import (
	"database/sql/driver"

	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

type EncryptedComplex128 struct {
	Raw complex128
}

func (EncryptedComplex128) GormDataType() string {
	return baseType
}

func (EncryptedComplex128) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *EncryptedComplex128) Scan(value interface{}) error {
	return decrypt(value.([]byte), s.Raw)
}

func (s EncryptedComplex128) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

type NullEncryptedComplex128 struct {
	Raw   complex128
	Empty bool
}

func (NullEncryptedComplex128) GormDataType() string {
	return baseType
}

func (NullEncryptedComplex128) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullEncryptedComplex128) Scan(value interface{}) error {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), s.Raw)
}

func (s NullEncryptedComplex128) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encrypt(s.Raw)
	}
}

type SignedComplex128 struct {
	Raw   complex128
	Valid bool
}

func (SignedComplex128) GormDataType() string {
	return baseType
}

func (SignedComplex128) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *SignedComplex128) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s SignedComplex128) Value() (driver.Value, error) {
	return sign(s.Raw)
}

type NullSignedComplex128 struct {
	Raw   complex128
	Empty bool
	Valid bool
}

func (NullSignedComplex128) GormDataType() string {
	return baseType
}

func (NullSignedComplex128) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullSignedComplex128) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = false
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedComplex128) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return sign(s.Raw)
	}
}

type SignedEncryptedComplex128 struct {
	Raw   complex128
	Valid bool
}

func (SignedEncryptedComplex128) GormDataType() string {
	return baseType
}

func (SignedEncryptedComplex128) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *SignedEncryptedComplex128) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s SignedEncryptedComplex128) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

type NullSignedEncryptedComplex128 struct {
	Raw   complex128
	Empty bool
	Valid bool
}

func (NullSignedEncryptedComplex128) GormDataType() string {
	return baseType
}

func (NullSignedEncryptedComplex128) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullSignedEncryptedComplex128) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = false
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedEncryptedComplex128) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encryptSign(s.Raw)
	}
}
