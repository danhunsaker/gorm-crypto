package gorm_crypto

import (
	"database/sql/driver"

	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

type EncryptedInt32 struct {
	Raw int32
}

func (EncryptedInt32) GormDataType() string {
	return baseType
}

func (EncryptedInt32) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *EncryptedInt32) Scan(value interface{}) error {
	return decrypt(value.([]byte), s.Raw)
}

func (s EncryptedInt32) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

type NullEncryptedInt32 struct {
	Raw   int32
	Empty bool
}

func (NullEncryptedInt32) GormDataType() string {
	return baseType
}

func (NullEncryptedInt32) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullEncryptedInt32) Scan(value interface{}) error {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), s.Raw)
}

func (s NullEncryptedInt32) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encrypt(s.Raw)
	}
}

type SignedInt32 struct {
	Raw   int32
	Valid bool
}

func (SignedInt32) GormDataType() string {
	return baseType
}

func (SignedInt32) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *SignedInt32) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s SignedInt32) Value() (driver.Value, error) {
	return sign(s.Raw)
}

type NullSignedInt32 struct {
	Raw   int32
	Empty bool
	Valid bool
}

func (NullSignedInt32) GormDataType() string {
	return baseType
}

func (NullSignedInt32) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullSignedInt32) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = false
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedInt32) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return sign(s.Raw)
	}
}

type SignedEncryptedInt32 struct {
	Raw   int32
	Valid bool
}

func (SignedEncryptedInt32) GormDataType() string {
	return baseType
}

func (SignedEncryptedInt32) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *SignedEncryptedInt32) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s SignedEncryptedInt32) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

type NullSignedEncryptedInt32 struct {
	Raw   int32
	Empty bool
	Valid bool
}

func (NullSignedEncryptedInt32) GormDataType() string {
	return baseType
}

func (NullSignedEncryptedInt32) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullSignedEncryptedInt32) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = false
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedEncryptedInt32) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encryptSign(s.Raw)
	}
}
