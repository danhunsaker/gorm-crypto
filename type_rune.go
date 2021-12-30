package gorm_crypto

import "database/sql/driver"

type EncryptedRune struct {
	Field
	Raw rune
}

func (s *EncryptedRune) Scan(value interface{}) error {
	return decrypt(value.([]byte), &s.Raw)
}

func (s EncryptedRune) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

type NullEncryptedRune struct {
	Field
	Raw   rune
	Empty bool
}

func (s *NullEncryptedRune) Scan(value interface{}) error {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), &s.Raw)
}

func (s NullEncryptedRune) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encrypt(s.Raw)
	}
}

type SignedRune struct {
	Field
	Raw   rune
	Valid bool
}

func (s *SignedRune) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s SignedRune) Value() (driver.Value, error) {
	return sign(s.Raw)
}

type NullSignedRune struct {
	Field
	Raw   rune
	Empty bool
	Valid bool
}

func (s *NullSignedRune) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
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
	Field
	Raw   rune
	Valid bool
}

func (s *SignedEncryptedRune) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s SignedEncryptedRune) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

type NullSignedEncryptedRune struct {
	Field
	Raw   rune
	Empty bool
	Valid bool
}

func (s *NullSignedEncryptedRune) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
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
