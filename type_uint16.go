package gorm_crypto

import (
	"database/sql/driver"

	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

type EncryptedUint16 struct {
	Raw uint16
}

func (EncryptedUint16) GormDataType() string {
	return baseType
}

func (EncryptedUint16) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *EncryptedUint16) Scan(value interface{}) error {
	return decrypt(value.([]byte), s.Raw)
}

func (s EncryptedUint16) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

type NullEncryptedUint16 struct {
	Raw   uint16
	Empty bool
}

func (NullEncryptedUint16) GormDataType() string {
	return baseType
}

func (NullEncryptedUint16) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullEncryptedUint16) Scan(value interface{}) error {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), s.Raw)
}

func (s NullEncryptedUint16) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encrypt(s.Raw)
	}
}

type SignedUint16 struct {
	Raw   uint16
	Valid bool
}

func (SignedUint16) GormDataType() string {
	return baseType
}

func (SignedUint16) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *SignedUint16) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s SignedUint16) Value() (driver.Value, error) {
	return sign(s.Raw)
}

type NullSignedUint16 struct {
	Raw   uint16
	Empty bool
	Valid bool
}

func (NullSignedUint16) GormDataType() string {
	return baseType
}

func (NullSignedUint16) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullSignedUint16) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = false
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedUint16) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return sign(s.Raw)
	}
}

type SignedEncryptedUint16 struct {
	Raw   uint16
	Valid bool
}

func (SignedEncryptedUint16) GormDataType() string {
	return baseType
}

func (SignedEncryptedUint16) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *SignedEncryptedUint16) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s SignedEncryptedUint16) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

type NullSignedEncryptedUint16 struct {
	Raw   uint16
	Empty bool
	Valid bool
}

func (NullSignedEncryptedUint16) GormDataType() string {
	return baseType
}

func (NullSignedEncryptedUint16) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullSignedEncryptedUint16) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = false
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedEncryptedUint16) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encryptSign(s.Raw)
	}
}
