package gorm_crypto

import (
	"database/sql/driver"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

type EncryptedTime struct {
	Raw time.Time
}

func (EncryptedTime) GormDataType() string {
	return baseType
}

func (EncryptedTime) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *EncryptedTime) Scan(value interface{}) error {
	return decrypt(value.([]byte), s.Raw)
}

func (s EncryptedTime) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

type NullEncryptedTime struct {
	Raw   time.Time
	Empty bool
}

func (NullEncryptedTime) GormDataType() string {
	return baseType
}

func (NullEncryptedTime) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullEncryptedTime) Scan(value interface{}) error {
	if value == nil {
		s.Raw = time.Time{}
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), s.Raw)
}

func (s NullEncryptedTime) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encrypt(s.Raw)
	}
}

type SignedTime struct {
	Raw   time.Time
	Valid bool
}

func (SignedTime) GormDataType() string {
	return baseType
}

func (SignedTime) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *SignedTime) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s SignedTime) Value() (driver.Value, error) {
	return sign(s.Raw)
}

type NullSignedTime struct {
	Raw   time.Time
	Empty bool
	Valid bool
}

func (NullSignedTime) GormDataType() string {
	return baseType
}

func (NullSignedTime) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullSignedTime) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = time.Time{}
		s.Empty = true
		s.Valid = false
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedTime) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return sign(s.Raw)
	}
}

type SignedEncryptedTime struct {
	Raw   time.Time
	Valid bool
}

func (SignedEncryptedTime) GormDataType() string {
	return baseType
}

func (SignedEncryptedTime) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *SignedEncryptedTime) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s SignedEncryptedTime) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

type NullSignedEncryptedTime struct {
	Raw   time.Time
	Empty bool
	Valid bool
}

func (NullSignedEncryptedTime) GormDataType() string {
	return baseType
}

func (NullSignedEncryptedTime) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullSignedEncryptedTime) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = time.Time{}
		s.Empty = true
		s.Valid = false
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedEncryptedTime) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encryptSign(s.Raw)
	}
}
