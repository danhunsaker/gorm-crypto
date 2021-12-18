package gorm_crypto

import (
	"database/sql/driver"

	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

type EncryptedRuneSlice struct {
	Raw []rune
}

func (EncryptedRuneSlice) GormDataType() string {
	return baseType
}

func (EncryptedRuneSlice) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *EncryptedRuneSlice) Scan(value interface{}) error {
	return decrypt(value.([]byte), s.Raw)
}

func (s EncryptedRuneSlice) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

type NullEncryptedRuneSlice struct {
	Raw   []rune
	Empty bool
}

func (NullEncryptedRuneSlice) GormDataType() string {
	return baseType
}

func (NullEncryptedRuneSlice) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullEncryptedRuneSlice) Scan(value interface{}) error {
	if value == nil {
		s.Raw = []rune{}
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), s.Raw)
}

func (s NullEncryptedRuneSlice) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encrypt(s.Raw)
	}
}

type SignedRuneSlice struct {
	Raw   []rune
	Valid bool
}

func (SignedRuneSlice) GormDataType() string {
	return baseType
}

func (SignedRuneSlice) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *SignedRuneSlice) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s SignedRuneSlice) Value() (driver.Value, error) {
	return sign(s.Raw)
}

type NullSignedRuneSlice struct {
	Raw   []rune
	Empty bool
	Valid bool
}

func (NullSignedRuneSlice) GormDataType() string {
	return baseType
}

func (NullSignedRuneSlice) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullSignedRuneSlice) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = []rune{}
		s.Empty = true
		s.Valid = false
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedRuneSlice) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return sign(s.Raw)
	}
}

type SignedEncryptedRuneSlice struct {
	Raw   []rune
	Valid bool
}

func (SignedEncryptedRuneSlice) GormDataType() string {
	return baseType
}

func (SignedEncryptedRuneSlice) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *SignedEncryptedRuneSlice) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s SignedEncryptedRuneSlice) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

type NullSignedEncryptedRuneSlice struct {
	Raw   []rune
	Empty bool
	Valid bool
}

func (NullSignedEncryptedRuneSlice) GormDataType() string {
	return baseType
}

func (NullSignedEncryptedRuneSlice) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return serverType(db, field)
}

func (s *NullSignedEncryptedRuneSlice) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = []rune{}
		s.Empty = true
		s.Valid = false
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedEncryptedRuneSlice) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encryptSign(s.Raw)
	}
}
