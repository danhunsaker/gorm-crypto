package gorm_crypto

import "database/sql/driver"

type EncryptedFloat64 struct {
	Field
	Raw float64
}

func (s *EncryptedFloat64) Scan(value interface{}) error {
	return decrypt(value.([]byte), &s.Raw)
}

func (s EncryptedFloat64) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

type NullEncryptedFloat64 struct {
	Field
	Raw   float64
	Empty bool
}

func (s *NullEncryptedFloat64) Scan(value interface{}) error {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), &s.Raw)
}

func (s NullEncryptedFloat64) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encrypt(s.Raw)
	}
}

type SignedFloat64 struct {
	Field
	Raw   float64
	Valid bool
}

func (s *SignedFloat64) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s SignedFloat64) Value() (driver.Value, error) {
	return sign(s.Raw)
}

type NullSignedFloat64 struct {
	Field
	Raw   float64
	Empty bool
	Valid bool
}

func (s *NullSignedFloat64) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedFloat64) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return sign(s.Raw)
	}
}

type SignedEncryptedFloat64 struct {
	Field
	Raw   float64
	Valid bool
}

func (s *SignedEncryptedFloat64) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s SignedEncryptedFloat64) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

type NullSignedEncryptedFloat64 struct {
	Field
	Raw   float64
	Empty bool
	Valid bool
}

func (s *NullSignedEncryptedFloat64) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedEncryptedFloat64) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encryptSign(s.Raw)
	}
}
