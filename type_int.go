package gorm_crypto

import (
	"database/sql/driver"

	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

type EncryptedInt struct {
	Raw int
}

func (EncryptedInt) GormDataType() string {
	return baseType
}

func (EncryptedInt) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *EncryptedInt) Scan(value interface{}) error {
	return decrypt(value.([]byte), s.Raw)
}

func (s EncryptedInt) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

type NullEncryptedInt struct {
	Raw   int
	Empty bool
}

func (NullEncryptedInt) GormDataType() string {
	return baseType
}

func (NullEncryptedInt) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullEncryptedInt) Scan(value interface{}) error {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), s.Raw)
}

func (s NullEncryptedInt) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encrypt(s.Raw)
	}
}

type SignedInt struct {
	Raw   int
	Valid bool
}

func (SignedInt) GormDataType() string {
	return baseType
}

func (SignedInt) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *SignedInt) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s SignedInt) Value() (driver.Value, error) {
	return sign(s.Raw)
}

type NullSignedInt struct {
	Raw   int
	Empty bool
	Valid bool
}

func (NullSignedInt) GormDataType() string {
	return baseType
}

func (NullSignedInt) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullSignedInt) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = false
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedInt) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return sign(s.Raw)
	}
}

type SignedEncryptedInt struct {
	Raw   int
	Valid bool
}

func (SignedEncryptedInt) GormDataType() string {
	return baseType
}

func (SignedEncryptedInt) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *SignedEncryptedInt) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s SignedEncryptedInt) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

type NullSignedEncryptedInt struct {
	Raw   int
	Empty bool
	Valid bool
}

func (NullSignedEncryptedInt) GormDataType() string {
	return baseType
}

func (NullSignedEncryptedInt) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullSignedEncryptedInt) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = false
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedEncryptedInt) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encryptSign(s.Raw)
	}
}
