package gorm_crypto

import (
	"database/sql/driver"

	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

type EncryptedFloat32 struct {
	Raw float32
}

func (EncryptedFloat32) GormDataType() string {
	return baseType
}

func (EncryptedFloat32) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *EncryptedFloat32) Scan(value interface{}) error {
	return decrypt(value.([]byte), s.Raw)
}

func (s EncryptedFloat32) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

type NullEncryptedFloat32 struct {
	Raw   float32
	Empty bool
}

func (NullEncryptedFloat32) GormDataType() string {
	return baseType
}

func (NullEncryptedFloat32) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullEncryptedFloat32) Scan(value interface{}) error {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), s.Raw)
}

func (s NullEncryptedFloat32) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encrypt(s.Raw)
	}
}

type SignedFloat32 struct {
	Raw   float32
	Valid bool
}

func (SignedFloat32) GormDataType() string {
	return baseType
}

func (SignedFloat32) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *SignedFloat32) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s SignedFloat32) Value() (driver.Value, error) {
	return sign(s.Raw)
}

type NullSignedFloat32 struct {
	Raw   float32
	Empty bool
	Valid bool
}

func (NullSignedFloat32) GormDataType() string {
	return baseType
}

func (NullSignedFloat32) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullSignedFloat32) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = false
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedFloat32) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return sign(s.Raw)
	}
}

type SignedEncryptedFloat32 struct {
	Raw   float32
	Valid bool
}

func (SignedEncryptedFloat32) GormDataType() string {
	return baseType
}

func (SignedEncryptedFloat32) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *SignedEncryptedFloat32) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s SignedEncryptedFloat32) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

type NullSignedEncryptedFloat32 struct {
	Raw   float32
	Empty bool
	Valid bool
}

func (NullSignedEncryptedFloat32) GormDataType() string {
	return baseType
}

func (NullSignedEncryptedFloat32) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullSignedEncryptedFloat32) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = false
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedEncryptedFloat32) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encryptSign(s.Raw)
	}
}
