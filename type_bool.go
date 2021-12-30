package gorm_crypto

import "database/sql/driver"

type EncryptedBool struct {
	Field
	Raw bool
}

func (s *EncryptedBool) Scan(value interface{}) error {
	return decrypt(value.([]byte), &s.Raw)
}

func (s EncryptedBool) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

type NullEncryptedBool struct {
	Field
	Raw   bool
	Empty bool
}

func (s *NullEncryptedBool) Scan(value interface{}) error {
	if value == nil {
		s.Raw = false
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), &s.Raw)
}

func (s NullEncryptedBool) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encrypt(s.Raw)
	}
}

type SignedBool struct {
	Field
	Raw   bool
	Valid bool
}

func (s *SignedBool) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s SignedBool) Value() (driver.Value, error) {
	return sign(s.Raw)
}

type NullSignedBool struct {
	Field
	Raw   bool
	Empty bool
	Valid bool
}

func (s *NullSignedBool) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = false
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedBool) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return sign(s.Raw)
	}
}

type SignedEncryptedBool struct {
	Field
	Raw   bool
	Valid bool
}

func (s *SignedEncryptedBool) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s SignedEncryptedBool) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

type NullSignedEncryptedBool struct {
	Field
	Raw   bool
	Empty bool
	Valid bool
}

func (s *NullSignedEncryptedBool) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = false
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedEncryptedBool) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encryptSign(s.Raw)
	}
}
