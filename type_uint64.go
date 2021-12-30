package gorm_crypto

import "database/sql/driver"

type EncryptedUint64 struct {
	Field
	Raw uint64
}

func (s *EncryptedUint64) Scan(value interface{}) error {
	return decrypt(value.([]byte), &s.Raw)
}

func (s EncryptedUint64) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

type NullEncryptedUint64 struct {
	Field
	Raw   uint64
	Empty bool
}

func (s *NullEncryptedUint64) Scan(value interface{}) error {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), &s.Raw)
}

func (s NullEncryptedUint64) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encrypt(s.Raw)
	}
}

type SignedUint64 struct {
	Field
	Raw   uint64
	Valid bool
}

func (s *SignedUint64) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s SignedUint64) Value() (driver.Value, error) {
	return sign(s.Raw)
}

type NullSignedUint64 struct {
	Field
	Raw   uint64
	Empty bool
	Valid bool
}

func (s *NullSignedUint64) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedUint64) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return sign(s.Raw)
	}
}

type SignedEncryptedUint64 struct {
	Field
	Raw   uint64
	Valid bool
}

func (s *SignedEncryptedUint64) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s SignedEncryptedUint64) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

type NullSignedEncryptedUint64 struct {
	Field
	Raw   uint64
	Empty bool
	Valid bool
}

func (s *NullSignedEncryptedUint64) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedEncryptedUint64) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encryptSign(s.Raw)
	}
}
