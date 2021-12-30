package gorm_crypto

import "database/sql/driver"

type EncryptedString struct {
	Field
	Raw string
}

func (s *EncryptedString) Scan(value interface{}) error {
	return decrypt(value.([]byte), &s.Raw)
}

func (s EncryptedString) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

type NullEncryptedString struct {
	Field
	Raw   string
	Empty bool
}

func (s *NullEncryptedString) Scan(value interface{}) error {
	if value == nil {
		s.Raw = ""
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), &s.Raw)
}

func (s NullEncryptedString) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encrypt(s.Raw)
	}
}

type SignedString struct {
	Field
	Raw   string
	Valid bool
}

func (s *SignedString) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s SignedString) Value() (driver.Value, error) {
	return sign(s.Raw)
}

type NullSignedString struct {
	Field
	Raw   string
	Empty bool
	Valid bool
}

func (s *NullSignedString) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = ""
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedString) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return sign(s.Raw)
	}
}

type SignedEncryptedString struct {
	Field
	Raw   string
	Valid bool
}

func (s *SignedEncryptedString) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s SignedEncryptedString) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

type NullSignedEncryptedString struct {
	Field
	Raw   string
	Empty bool
	Valid bool
}

func (s *NullSignedEncryptedString) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = ""
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedEncryptedString) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encryptSign(s.Raw)
	}
}
