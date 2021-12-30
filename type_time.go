package gorm_crypto

import (
	"database/sql/driver"
	"time"
)

type EncryptedTime struct {
	Field
	Raw time.Time
}

func (s *EncryptedTime) Scan(value interface{}) error {
	return decrypt(value.([]byte), &s.Raw)
}

func (s EncryptedTime) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

type NullEncryptedTime struct {
	Field
	Raw   time.Time
	Empty bool
}

func (s *NullEncryptedTime) Scan(value interface{}) error {
	if value == nil {
		s.Raw = time.Time{}
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), &s.Raw)
}

func (s NullEncryptedTime) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encrypt(s.Raw)
	}
}

type SignedTime struct {
	Field
	Raw   time.Time
	Valid bool
}

func (s *SignedTime) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s SignedTime) Value() (driver.Value, error) {
	return sign(s.Raw)
}

type NullSignedTime struct {
	Field
	Raw   time.Time
	Empty bool
	Valid bool
}

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

func (s NullSignedTime) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return sign(s.Raw)
	}
}

type SignedEncryptedTime struct {
	Field
	Raw   time.Time
	Valid bool
}

func (s *SignedEncryptedTime) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s SignedEncryptedTime) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

type NullSignedEncryptedTime struct {
	Field
	Raw   time.Time
	Empty bool
	Valid bool
}

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

func (s NullSignedEncryptedTime) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encryptSign(s.Raw)
	}
}
