package gormcrypto

import (
	"database/sql/driver"
	"time"
)

// EncryptedTime supports encrypting Time data
type EncryptedTime struct {
	Field
	Raw time.Time
}

// Scan converts the value from the DB into a usable EncryptedTime value
func (s *EncryptedTime) Scan(value interface{}) error {
	return decrypt(value.([]byte), &s.Raw)
}

// Value converts an initialized EncryptedTime value into a value that can safely be stored in the DB
func (s EncryptedTime) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

// NullEncryptedTime supports encrypting nullable Time data
type NullEncryptedTime struct {
	Field
	Raw   time.Time
	Empty bool
}

// Scan converts the value from the DB into a usable NullEncryptedTime value
func (s *NullEncryptedTime) Scan(value interface{}) error {
	if value == nil {
		s.Raw = time.Time{}
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), &s.Raw)
}

// Value converts an initialized NullEncryptedTime value into a value that can safely be stored in the DB
func (s NullEncryptedTime) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return encrypt(s.Raw)
}

// SignedTime supports signing Time data
type SignedTime struct {
	Field
	Raw   time.Time
	Valid bool
}

// Scan converts the value from the DB into a usable SignedTime value
func (s *SignedTime) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized SignedTime value into a value that can safely be stored in the DB
func (s SignedTime) Value() (driver.Value, error) {
	return sign(s.Raw)
}

// NullSignedTime supports signing nullable Time data
type NullSignedTime struct {
	Field
	Raw   time.Time
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedTime value
func (s *NullSignedTime) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = time.Time{}
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized NullSignedTime value into a value that can safely be stored in the DB
func (s NullSignedTime) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return sign(s.Raw)
}

// SignedEncryptedTime supports signing and encrypting Time data
type SignedEncryptedTime struct {
	Field
	Raw   time.Time
	Valid bool
}

// Scan converts the value from the DB into a usable SignedEncryptedTime value
func (s *SignedEncryptedTime) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized SignedEncryptedTime value into a value that can safely be stored in the DB
func (s SignedEncryptedTime) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

// NullSignedEncryptedTime supports signing and encrypting nullable Time data
type NullSignedEncryptedTime struct {
	Field
	Raw   time.Time
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedEncryptedTime value
func (s *NullSignedEncryptedTime) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = time.Time{}
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized NullSignedEncryptedTime value into a value that can safely be stored in the DB
func (s NullSignedEncryptedTime) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return encryptSign(s.Raw)
}
