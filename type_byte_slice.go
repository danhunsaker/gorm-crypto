package gorm_crypto

import "database/sql/driver"

type EncryptedByteSlice struct {
	Field
	Raw []byte
}

func (s *EncryptedByteSlice) Scan(value interface{}) error {
	return decrypt(value.([]byte), &s.Raw)
}

func (s EncryptedByteSlice) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

type NullEncryptedByteSlice struct {
	Field
	Raw   []byte
	Empty bool
}

func (s *NullEncryptedByteSlice) Scan(value interface{}) error {
	if value == nil {
		s.Raw = []byte{}
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), &s.Raw)
}

func (s NullEncryptedByteSlice) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encrypt(s.Raw)
	}
}

type SignedByteSlice struct {
	Field
	Raw   []byte
	Valid bool
}

func (s *SignedByteSlice) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s SignedByteSlice) Value() (driver.Value, error) {
	return sign(s.Raw)
}

type NullSignedByteSlice struct {
	Field
	Raw   []byte
	Empty bool
	Valid bool
}

func (s *NullSignedByteSlice) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = []byte{}
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedByteSlice) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return sign(s.Raw)
	}
}

type SignedEncryptedByteSlice struct {
	Field
	Raw   []byte
	Valid bool
}

func (s *SignedEncryptedByteSlice) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s SignedEncryptedByteSlice) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

type NullSignedEncryptedByteSlice struct {
	Field
	Raw   []byte
	Empty bool
	Valid bool
}

func (s *NullSignedEncryptedByteSlice) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = []byte{}
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

func (s NullSignedEncryptedByteSlice) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		return encryptSign(s.Raw)
	}
}
