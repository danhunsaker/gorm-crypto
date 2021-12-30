package gorm_crypto

import "database/sql/driver"

type EncryptedUint32 struct {
	Field
	Raw uint32
}

func (s *EncryptedUint32) Scan(value interface{}) error {
	return decrypt(value.([]byte), &s.Raw)
}

func (s EncryptedUint32) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

type NullEncryptedUint32 struct {
	Field
	Raw   uint32
	Empty bool
}

func (s *NullEncryptedUint32) Scan(value interface{}) error {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), &s.Raw)
}

func (s NullEncryptedUint32) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encrypt(s.Raw)
	}
}

type SignedUint32 struct {
	Field
	Raw   uint32
	Valid bool
}

func (s *SignedUint32) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s SignedUint32) Value() (driver.Value, error) {
	return sign(s.Raw)
}

type NullSignedUint32 struct {
	Field
	Raw   uint32
	Empty bool
	Valid bool
}

func (s *NullSignedUint32) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedUint32) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return sign(s.Raw)
	}
}

type SignedEncryptedUint32 struct {
	Field
	Raw   uint32
	Valid bool
}

func (s *SignedEncryptedUint32) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s SignedEncryptedUint32) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

type NullSignedEncryptedUint32 struct {
	Field
	Raw   uint32
	Empty bool
	Valid bool
}

func (s *NullSignedEncryptedUint32) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedEncryptedUint32) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encryptSign(s.Raw)
	}
}
