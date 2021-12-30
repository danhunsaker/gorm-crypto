package gorm_crypto

import "database/sql/driver"

type EncryptedInt struct {
	Field
	Raw int
}

func (s *EncryptedInt) Scan(value interface{}) error {
	return decrypt(value.([]byte), &s.Raw)
}

func (s EncryptedInt) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

type NullEncryptedInt struct {
	Field
	Raw   int
	Empty bool
}

func (s *NullEncryptedInt) Scan(value interface{}) error {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), &s.Raw)
}

func (s NullEncryptedInt) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encrypt(s.Raw)
	}
}

type SignedInt struct {
	Field
	Raw   int
	Valid bool
}

func (s *SignedInt) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s SignedInt) Value() (driver.Value, error) {
	return sign(s.Raw)
}

type NullSignedInt struct {
	Field
	Raw   int
	Empty bool
	Valid bool
}

func (s *NullSignedInt) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedInt) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return sign(s.Raw)
	}
}

type SignedEncryptedInt struct {
	Field
	Raw   int
	Valid bool
}

func (s *SignedEncryptedInt) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s SignedEncryptedInt) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

type NullSignedEncryptedInt struct {
	Field
	Raw   int
	Empty bool
	Valid bool
}

func (s *NullSignedEncryptedInt) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedEncryptedInt) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encryptSign(s.Raw)
	}
}
