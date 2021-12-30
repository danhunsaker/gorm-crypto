package gorm_crypto

import "database/sql/driver"

type EncryptedUint struct {
	Field
	Raw uint
}

func (s *EncryptedUint) Scan(value interface{}) error {
	return decrypt(value.([]byte), &s.Raw)
}

func (s EncryptedUint) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

type NullEncryptedUint struct {
	Field
	Raw   uint
	Empty bool
}

func (s *NullEncryptedUint) Scan(value interface{}) error {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), &s.Raw)
}

func (s NullEncryptedUint) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encrypt(s.Raw)
	}
}

type SignedUint struct {
	Field
	Raw   uint
	Valid bool
}

func (s *SignedUint) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s SignedUint) Value() (driver.Value, error) {
	return sign(s.Raw)
}

type NullSignedUint struct {
	Field
	Raw   uint
	Empty bool
	Valid bool
}

func (s *NullSignedUint) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedUint) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return sign(s.Raw)
	}
}

type SignedEncryptedUint struct {
	Field
	Raw   uint
	Valid bool
}

func (s *SignedEncryptedUint) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s SignedEncryptedUint) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

type NullSignedEncryptedUint struct {
	Field
	Raw   uint
	Empty bool
	Valid bool
}

func (s *NullSignedEncryptedUint) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedEncryptedUint) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encryptSign(s.Raw)
	}
}
