package gorm_crypto

import "database/sql/driver"

type EncryptedInt16 struct {
	Field
	Raw int16
}

func (s *EncryptedInt16) Scan(value interface{}) error {
	return decrypt(value.([]byte), &s.Raw)
}

func (s EncryptedInt16) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

type NullEncryptedInt16 struct {
	Field
	Raw   int16
	Empty bool
}

func (s *NullEncryptedInt16) Scan(value interface{}) error {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), &s.Raw)
}

func (s NullEncryptedInt16) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encrypt(s.Raw)
	}
}

type SignedInt16 struct {
	Field
	Raw   int16
	Valid bool
}

func (s *SignedInt16) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s SignedInt16) Value() (driver.Value, error) {
	return sign(s.Raw)
}

type NullSignedInt16 struct {
	Field
	Raw   int16
	Empty bool
	Valid bool
}

func (s *NullSignedInt16) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedInt16) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return sign(s.Raw)
	}
}

type SignedEncryptedInt16 struct {
	Field
	Raw   int16
	Valid bool
}

func (s *SignedEncryptedInt16) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s SignedEncryptedInt16) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

type NullSignedEncryptedInt16 struct {
	Field
	Raw   int16
	Empty bool
	Valid bool
}

func (s *NullSignedEncryptedInt16) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedEncryptedInt16) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encryptSign(s.Raw)
	}
}
