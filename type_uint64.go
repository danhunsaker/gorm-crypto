package gorm_crypto

import (
	"database/sql/driver"

	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

type EncryptedUint64 struct {
	Raw uint64
}

func (EncryptedUint64) GormDataType() string {
	return baseType
}

func (EncryptedUint64) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *EncryptedUint64) Scan(value interface{}) error {
	return decrypt(value.([]byte), s.Raw)
}

func (s EncryptedUint64) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

type NullEncryptedUint64 struct {
	Raw   uint64
	Empty bool
}

func (NullEncryptedUint64) GormDataType() string {
	return baseType
}

func (NullEncryptedUint64) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullEncryptedUint64) Scan(value interface{}) error {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), s.Raw)
}

func (s NullEncryptedUint64) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encrypt(s.Raw)
	}
}

type SignedUint64 struct {
	Raw   uint64
	Valid bool
}

func (SignedUint64) GormDataType() string {
	return baseType
}

func (SignedUint64) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *SignedUint64) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s SignedUint64) Value() (driver.Value, error) {
	return sign(s.Raw)
}

type NullSignedUint64 struct {
	Raw   uint64
	Empty bool
	Valid bool
}

func (NullSignedUint64) GormDataType() string {
	return baseType
}

func (NullSignedUint64) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullSignedUint64) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = false
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedUint64) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return sign(s.Raw)
	}
}

type SignedEncryptedUint64 struct {
	Raw   uint64
	Valid bool
}

func (SignedEncryptedUint64) GormDataType() string {
	return baseType
}

func (SignedEncryptedUint64) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *SignedEncryptedUint64) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s SignedEncryptedUint64) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

type NullSignedEncryptedUint64 struct {
	Raw   uint64
	Empty bool
	Valid bool
}

func (NullSignedEncryptedUint64) GormDataType() string {
	return baseType
}

func (NullSignedEncryptedUint64) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullSignedEncryptedUint64) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = false
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedEncryptedUint64) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encryptSign(s.Raw)
	}
}
