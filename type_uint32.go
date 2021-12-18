package gorm_crypto

import (
	"database/sql/driver"

	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

type EncryptedUint32 struct {
	Raw uint32
}

func (EncryptedUint32) GormDataType() string {
	return baseType
}

func (EncryptedUint32) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *EncryptedUint32) Scan(value interface{}) error {
	return decrypt(value.([]byte), s.Raw)
}

func (s EncryptedUint32) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

type NullEncryptedUint32 struct {
	Raw   uint32
	Empty bool
}

func (NullEncryptedUint32) GormDataType() string {
	return baseType
}

func (NullEncryptedUint32) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullEncryptedUint32) Scan(value interface{}) error {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), s.Raw)
}

func (s NullEncryptedUint32) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encrypt(s.Raw)
	}
}

type SignedUint32 struct {
	Raw   uint32
	Valid bool
}

func (SignedUint32) GormDataType() string {
	return baseType
}

func (SignedUint32) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *SignedUint32) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s SignedUint32) Value() (driver.Value, error) {
	return sign(s.Raw)
}

type NullSignedUint32 struct {
	Raw   uint32
	Empty bool
	Valid bool
}

func (NullSignedUint32) GormDataType() string {
	return baseType
}

func (NullSignedUint32) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullSignedUint32) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = false
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedUint32) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return sign(s.Raw)
	}
}

type SignedEncryptedUint32 struct {
	Raw   uint32
	Valid bool
}

func (SignedEncryptedUint32) GormDataType() string {
	return baseType
}

func (SignedEncryptedUint32) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *SignedEncryptedUint32) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s SignedEncryptedUint32) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

type NullSignedEncryptedUint32 struct {
	Raw   uint32
	Empty bool
	Valid bool
}

func (NullSignedEncryptedUint32) GormDataType() string {
	return baseType
}

func (NullSignedEncryptedUint32) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullSignedEncryptedUint32) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = false
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedEncryptedUint32) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encryptSign(s.Raw)
	}
}
