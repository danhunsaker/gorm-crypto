package gorm_crypto

import "database/sql/driver"

type EncryptedAny struct {
	Field
	Raw interface{}
}

func (s *EncryptedAny) Scan(value interface{}) error {
	return decrypt(value.([]byte), &s.Raw)
}

func (s EncryptedAny) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

type NullEncryptedAny struct {
	Field
	Raw   interface{}
	Empty bool
}

func (s *NullEncryptedAny) Scan(value interface{}) error {
	if value == nil {
		s.Raw = nil
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), &s.Raw)
}

func (s NullEncryptedAny) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encrypt(s.Raw)
	}
}

type SignedAny struct {
	Field
	Raw   interface{}
	Valid bool
}

func (s *SignedAny) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s SignedAny) Value() (driver.Value, error) {
	return sign(s.Raw)
}

type NullSignedAny struct {
	Field
	Raw   interface{}
	Empty bool
	Valid bool
}

func (s *NullSignedAny) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = nil
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedAny) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return sign(s.Raw)
	}
}

type SignedEncryptedAny struct {
	Field
	Raw   interface{}
	Valid bool
}

func (s *SignedEncryptedAny) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s SignedEncryptedAny) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

type NullSignedEncryptedAny struct {
	Field
	Raw   interface{}
	Empty bool
	Valid bool
}

func (s *NullSignedEncryptedAny) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = nil
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedEncryptedAny) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encryptSign(s.Raw)
	}
}
