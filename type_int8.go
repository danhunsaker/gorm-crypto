package gorm_crypto

import "database/sql/driver"

type EncryptedInt8 struct {
	Field
	Raw int8
}

func (s *EncryptedInt8) Scan(value interface{}) error {
	return decrypt(value.([]byte), &s.Raw)
}

func (s EncryptedInt8) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

type NullEncryptedInt8 struct {
	Field
	Raw   int8
	Empty bool
}

func (s *NullEncryptedInt8) Scan(value interface{}) error {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), &s.Raw)
}

func (s NullEncryptedInt8) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encrypt(s.Raw)
	}
}

type SignedInt8 struct {
	Field
	Raw   int8
	Valid bool
}

func (s *SignedInt8) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s SignedInt8) Value() (driver.Value, error) {
	return sign(s.Raw)
}

type NullSignedInt8 struct {
	Field
	Raw   int8
	Empty bool
	Valid bool
}

func (s *NullSignedInt8) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedInt8) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return sign(s.Raw)
	}
}

type SignedEncryptedInt8 struct {
	Field
	Raw   int8
	Valid bool
}

func (s *SignedEncryptedInt8) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s SignedEncryptedInt8) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

type NullSignedEncryptedInt8 struct {
	Field
	Raw   int8
	Empty bool
	Valid bool
}

func (s *NullSignedEncryptedInt8) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedEncryptedInt8) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encryptSign(s.Raw)
	}
}
