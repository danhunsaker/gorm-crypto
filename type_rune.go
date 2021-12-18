package gorm_crypto

import (
	"database/sql/driver"

	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

type EncryptedRune struct {
	Raw rune
}

func (EncryptedRune) GormDataType() string {
	return baseType
}

func (EncryptedRune) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *EncryptedRune) Scan(value interface{}) error {
	return decrypt(value.([]byte), s.Raw)
}

func (s EncryptedRune) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

type NullEncryptedRune struct {
	Raw   rune
	Empty bool
}

func (NullEncryptedRune) GormDataType() string {
	return baseType
}

func (NullEncryptedRune) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullEncryptedRune) Scan(value interface{}) error {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), s.Raw)
}

func (s NullEncryptedRune) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encrypt(s.Raw)
	}
}

type SignedRune struct {
	Raw   rune
	Valid bool
}

func (SignedRune) GormDataType() string {
	return baseType
}

func (SignedRune) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *SignedRune) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s SignedRune) Value() (driver.Value, error) {
	return sign(s.Raw)
}

type NullSignedRune struct {
	Raw   rune
	Empty bool
	Valid bool
}

func (NullSignedRune) GormDataType() string {
	return baseType
}

func (NullSignedRune) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullSignedRune) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = false
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedRune) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return sign(s.Raw)
	}
}

type SignedEncryptedRune struct {
	Raw   rune
	Valid bool
}

func (SignedEncryptedRune) GormDataType() string {
	return baseType
}

func (SignedEncryptedRune) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *SignedEncryptedRune) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s SignedEncryptedRune) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

type NullSignedEncryptedRune struct {
	Raw   rune
	Empty bool
	Valid bool
}

func (NullSignedEncryptedRune) GormDataType() string {
	return baseType
}

func (NullSignedEncryptedRune) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullSignedEncryptedRune) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = false
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedEncryptedRune) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encryptSign(s.Raw)
	}
}
