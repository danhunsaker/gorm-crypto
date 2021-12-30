package gorm_crypto

import "database/sql/driver"

type EncryptedRuneSlice struct {
	Field
	Raw []rune
}

func (s *EncryptedRuneSlice) Scan(value interface{}) error {
	return decrypt(value.([]byte), &s.Raw)
}

func (s EncryptedRuneSlice) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

type NullEncryptedRuneSlice struct {
	Field
	Raw   []rune
	Empty bool
}

func (s *NullEncryptedRuneSlice) Scan(value interface{}) error {
	if value == nil {
		s.Raw = []rune{}
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), &s.Raw)
}

func (s NullEncryptedRuneSlice) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encrypt(s.Raw)
	}
}

type SignedRuneSlice struct {
	Field
	Raw   []rune
	Valid bool
}

func (s *SignedRuneSlice) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s SignedRuneSlice) Value() (driver.Value, error) {
	return sign(s.Raw)
}

type NullSignedRuneSlice struct {
	Field
	Raw   []rune
	Empty bool
	Valid bool
}

func (s *NullSignedRuneSlice) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = []rune{}
		s.Empty = true
		s.Valid = true
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
	Field
	Raw   []rune
	Valid bool
}

func (s *SignedEncryptedRuneSlice) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s SignedEncryptedRuneSlice) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

type NullSignedEncryptedRuneSlice struct {
	Field
	Raw   []rune
	Empty bool
	Valid bool
}

func (s *NullSignedEncryptedRuneSlice) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = []rune{}
		s.Empty = true
		s.Valid = true
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
