package gorm_crypto

import "database/sql/driver"

type EncryptedFloat32 struct {
	Field
	Raw float32
}

func (s *EncryptedFloat32) Scan(value interface{}) error {
	return decrypt(value.([]byte), &s.Raw)
}

func (s EncryptedFloat32) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

type NullEncryptedFloat32 struct {
	Field
	Raw   float32
	Empty bool
}

func (s *NullEncryptedFloat32) Scan(value interface{}) error {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), &s.Raw)
}

func (s NullEncryptedFloat32) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encrypt(s.Raw)
	}
}

type SignedFloat32 struct {
	Field
	Raw   float32
	Valid bool
}

func (s *SignedFloat32) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s SignedFloat32) Value() (driver.Value, error) {
	return sign(s.Raw)
}

type NullSignedFloat32 struct {
	Field
	Raw   float32
	Empty bool
	Valid bool
}

func (s *NullSignedFloat32) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedFloat32) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return sign(s.Raw)
	}
}

type SignedEncryptedFloat32 struct {
	Field
	Raw   float32
	Valid bool
}

func (s *SignedEncryptedFloat32) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s SignedEncryptedFloat32) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

type NullSignedEncryptedFloat32 struct {
	Field
	Raw   float32
	Empty bool
	Valid bool
}

func (s *NullSignedEncryptedFloat32) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedEncryptedFloat32) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encryptSign(s.Raw)
	}
}
