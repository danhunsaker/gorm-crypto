package gorm_crypto

import "database/sql/driver"

type EncryptedUint16 struct {
	Field
	Raw uint16
}

func (s *EncryptedUint16) Scan(value interface{}) error {
	return decrypt(value.([]byte), &s.Raw)
}

func (s EncryptedUint16) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

type NullEncryptedUint16 struct {
	Field
	Raw   uint16
	Empty bool
}

func (s *NullEncryptedUint16) Scan(value interface{}) error {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), &s.Raw)
}

func (s NullEncryptedUint16) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encrypt(s.Raw)
	}
}

type SignedUint16 struct {
	Field
	Raw   uint16
	Valid bool
}

func (s *SignedUint16) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s SignedUint16) Value() (driver.Value, error) {
	return sign(s.Raw)
}

type NullSignedUint16 struct {
	Field
	Raw   uint16
	Empty bool
	Valid bool
}

func (s *NullSignedUint16) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedUint16) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return sign(s.Raw)
	}
}

type SignedEncryptedUint16 struct {
	Field
	Raw   uint16
	Valid bool
}

func (s *SignedEncryptedUint16) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s SignedEncryptedUint16) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

type NullSignedEncryptedUint16 struct {
	Field
	Raw   uint16
	Empty bool
	Valid bool
}

func (s *NullSignedEncryptedUint16) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedEncryptedUint16) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encryptSign(s.Raw)
	}
}
