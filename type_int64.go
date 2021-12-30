package gorm_crypto

import "database/sql/driver"

type EncryptedInt64 struct {
	Field
	Raw int64
}

func (s *EncryptedInt64) Scan(value interface{}) error {
	return decrypt(value.([]byte), &s.Raw)
}

func (s EncryptedInt64) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

type NullEncryptedInt64 struct {
	Field
	Raw   int64
	Empty bool
}

func (s *NullEncryptedInt64) Scan(value interface{}) error {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), &s.Raw)
}

func (s NullEncryptedInt64) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encrypt(s.Raw)
	}
}

type SignedInt64 struct {
	Field
	Raw   int64
	Valid bool
}

func (s *SignedInt64) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s SignedInt64) Value() (driver.Value, error) {
	return sign(s.Raw)
}

type NullSignedInt64 struct {
	Field
	Raw   int64
	Empty bool
	Valid bool
}

func (s *NullSignedInt64) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedInt64) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return sign(s.Raw)
	}
}

type SignedEncryptedInt64 struct {
	Field
	Raw   int64
	Valid bool
}

func (s *SignedEncryptedInt64) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s SignedEncryptedInt64) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

type NullSignedEncryptedInt64 struct {
	Field
	Raw   int64
	Empty bool
	Valid bool
}

func (s *NullSignedEncryptedInt64) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedEncryptedInt64) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encryptSign(s.Raw)
	}
}
