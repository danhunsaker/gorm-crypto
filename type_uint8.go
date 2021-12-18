package gorm_crypto

import (
	"database/sql/driver"

	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

type EncryptedUint8 struct {
	Raw uint8
}

func (EncryptedUint8) GormDataType() string {
	return baseType
}

func (EncryptedUint8) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *EncryptedUint8) Scan(value interface{}) error {
	return decrypt(value.([]byte), s.Raw)
}

func (s EncryptedUint8) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

type NullEncryptedUint8 struct {
	Raw   uint8
	Empty bool
}

func (NullEncryptedUint8) GormDataType() string {
	return baseType
}

func (NullEncryptedUint8) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullEncryptedUint8) Scan(value interface{}) error {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), s.Raw)
}

func (s NullEncryptedUint8) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encrypt(s.Raw)
	}
}

type SignedUint8 struct {
	Raw   uint8
	Valid bool
}

func (SignedUint8) GormDataType() string {
	return baseType
}

func (SignedUint8) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *SignedUint8) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s SignedUint8) Value() (driver.Value, error) {
	return sign(s.Raw)
}

type NullSignedUint8 struct {
	Raw   uint8
	Empty bool
	Valid bool
}

func (NullSignedUint8) GormDataType() string {
	return baseType
}

func (NullSignedUint8) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullSignedUint8) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = false
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedUint8) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return sign(s.Raw)
	}
}

type SignedEncryptedUint8 struct {
	Raw   uint8
	Valid bool
}

func (SignedEncryptedUint8) GormDataType() string {
	return baseType
}

func (SignedEncryptedUint8) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *SignedEncryptedUint8) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s SignedEncryptedUint8) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

type NullSignedEncryptedUint8 struct {
	Raw   uint8
	Empty bool
	Valid bool
}

func (NullSignedEncryptedUint8) GormDataType() string {
	return baseType
}

func (NullSignedEncryptedUint8) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullSignedEncryptedUint8) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = false
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedEncryptedUint8) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encryptSign(s.Raw)
	}
}
