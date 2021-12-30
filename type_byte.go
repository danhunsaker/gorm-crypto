package gorm_crypto

import "database/sql/driver"

type EncryptedByte struct {
	Field
	Raw byte
}

func (s *EncryptedByte) Scan(value interface{}) error {
	return decrypt(value.([]byte), &s.Raw)
}

func (s EncryptedByte) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

type NullEncryptedByte struct {
	Field
	Raw   byte
	Empty bool
}

func (s *NullEncryptedByte) Scan(value interface{}) error {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), &s.Raw)
}

func (s NullEncryptedByte) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encrypt(s.Raw)
	}
}

type SignedByte struct {
	Field
	Raw   byte
	Valid bool
}

func (s *SignedByte) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s SignedByte) Value() (driver.Value, error) {
	return sign(s.Raw)
}

type NullSignedByte struct {
	Field
	Raw   byte
	Empty bool
	Valid bool
}

func (s *NullSignedByte) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedByte) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return sign(s.Raw)
	}
}

type SignedEncryptedByte struct {
	Field
	Raw   byte
	Valid bool
}

func (s *SignedEncryptedByte) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s SignedEncryptedByte) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

type NullSignedEncryptedByte struct {
	Field
	Raw   byte
	Empty bool
	Valid bool
}

func (s *NullSignedEncryptedByte) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedEncryptedByte) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encryptSign(s.Raw)
	}
}
