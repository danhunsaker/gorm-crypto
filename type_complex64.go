package gorm_crypto

import (
	"database/sql/driver"

	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

type EncryptedComplex64 struct {
	Raw complex64
}

func (EncryptedComplex64) GormDataType() string {
	return baseType
}

func (EncryptedComplex64) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *EncryptedComplex64) Scan(value interface{}) error {
	return decrypt(value.([]byte), s.Raw)
}

func (s EncryptedComplex64) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

type NullEncryptedComplex64 struct {
	Raw   complex64
	Empty bool
}

func (NullEncryptedComplex64) GormDataType() string {
	return baseType
}

func (NullEncryptedComplex64) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullEncryptedComplex64) Scan(value interface{}) error {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), s.Raw)
}

func (s NullEncryptedComplex64) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encrypt(s.Raw)
	}
}

type SignedComplex64 struct {
	Raw   complex64
	Valid bool
}

func (SignedComplex64) GormDataType() string {
	return baseType
}

func (SignedComplex64) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *SignedComplex64) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s SignedComplex64) Value() (driver.Value, error) {
	return sign(s.Raw)
}

type NullSignedComplex64 struct {
	Raw   complex64
	Empty bool
	Valid bool
}

func (NullSignedComplex64) GormDataType() string {
	return baseType
}

func (NullSignedComplex64) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullSignedComplex64) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = false
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedComplex64) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return sign(s.Raw)
	}
}

type SignedEncryptedComplex64 struct {
	Raw   complex64
	Valid bool
}

func (SignedEncryptedComplex64) GormDataType() string {
	return baseType
}

func (SignedEncryptedComplex64) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *SignedEncryptedComplex64) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s SignedEncryptedComplex64) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

type NullSignedEncryptedComplex64 struct {
	Raw   complex64
	Empty bool
	Valid bool
}

func (NullSignedEncryptedComplex64) GormDataType() string {
	return baseType
}

func (NullSignedEncryptedComplex64) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullSignedEncryptedComplex64) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = false
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedEncryptedComplex64) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encryptSign(s.Raw)
	}
}
