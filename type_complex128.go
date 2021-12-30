package gc

import (
	"bytes"
	"database/sql/driver"
	"encoding/binary"
)

// EncryptedComplex128 supports encrypting Complex128 data
type EncryptedComplex128 struct {
	Field
	Raw complex128
}

// Scan converts the value from the DB into a usable EncryptedComplex128 value
func (s *EncryptedComplex128) Scan(value interface{}) error {
	var bin []byte
	err := decrypt(value.([]byte), &bin)
	if err != nil {
		return err
	}

	return binary.Read(bytes.NewBuffer(bin), binary.LittleEndian, &s.Raw)
}

// Value converts an initialized EncryptedComplex128 value into a value that can safely be stored in the DB
func (s EncryptedComplex128) Value() (driver.Value, error) {
	var bin bytes.Buffer
	err := binary.Write(&bin, binary.LittleEndian, s.Raw)
	if err != nil {
		return nil, err
	}
	return encrypt(bin.Bytes())
}

// NullEncryptedComplex128 supports encrypting nullable Complex128 data
type NullEncryptedComplex128 struct {
	Field
	Raw   complex128
	Empty bool
}

// Scan converts the value from the DB into a usable NullEncryptedComplex128 value
func (s *NullEncryptedComplex128) Scan(value interface{}) error {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		return nil
	}

	var bin []byte
	err := decrypt(value.([]byte), &bin)
	if err != nil {
		return err
	}

	return binary.Read(bytes.NewBuffer(bin), binary.LittleEndian, &s.Raw)
}

// Value converts an initialized NullEncryptedComplex128 value into a value that can safely be stored in the DB
func (s NullEncryptedComplex128) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	var bin bytes.Buffer
	err := binary.Write(&bin, binary.LittleEndian, s.Raw)
	if err != nil {
		return nil, err
	}
	return encrypt(bin.Bytes())
}

// SignedComplex128 supports signing Complex128 data
type SignedComplex128 struct {
	Field
	Raw   complex128
	Valid bool
}

// Scan converts the value from the DB into a usable SignedComplex128 value
func (s *SignedComplex128) Scan(value interface{}) (err error) {
	var bin []byte
	s.Valid, err = verify(value.([]byte), &bin)
	if err != nil {
		return err
	}

	return binary.Read(bytes.NewBuffer(bin), binary.LittleEndian, &s.Raw)
}

// Value converts an initialized SignedComplex128 value into a value that can safely be stored in the DB
func (s SignedComplex128) Value() (driver.Value, error) {
	var bin bytes.Buffer
	err := binary.Write(&bin, binary.LittleEndian, s.Raw)
	if err != nil {
		return nil, err
	}
	return sign(bin.Bytes())
}

// NullSignedComplex128 supports signing nullable Complex128 data
type NullSignedComplex128 struct {
	Field
	Raw   complex128
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedComplex128 value
func (s *NullSignedComplex128) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	var bin []byte
	s.Valid, err = verify(value.([]byte), &bin)
	if err != nil {
		return err
	}

	return binary.Read(bytes.NewBuffer(bin), binary.LittleEndian, &s.Raw)
}

// Value converts an initialized NullSignedComplex128 value into a value that can safely be stored in the DB
func (s NullSignedComplex128) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	var bin bytes.Buffer
	err := binary.Write(&bin, binary.LittleEndian, s.Raw)
	if err != nil {
		return nil, err
	}
	return sign(bin.Bytes())
}

// SignedEncryptedComplex128 supports signing and encrypting Complex128 data
type SignedEncryptedComplex128 struct {
	Field
	Raw   complex128
	Valid bool
}

// Scan converts the value from the DB into a usable SignedEncryptedComplex128 value
func (s *SignedEncryptedComplex128) Scan(value interface{}) (err error) {
	var bin []byte
	s.Valid, err = decryptVerify(value.([]byte), &bin)
	if err != nil {
		return err
	}

	return binary.Read(bytes.NewBuffer(bin), binary.LittleEndian, &s.Raw)
}

// Value converts an initialized SignedEncryptedComplex128 value into a value that can safely be stored in the DB
func (s SignedEncryptedComplex128) Value() (driver.Value, error) {
	var bin bytes.Buffer
	err := binary.Write(&bin, binary.LittleEndian, s.Raw)
	if err != nil {
		return nil, err
	}
	return encryptSign(bin.Bytes())
}

// NullSignedEncryptedComplex128 supports signing and encrypting nullable Complex128 data
type NullSignedEncryptedComplex128 struct {
	Field
	Raw   complex128
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedEncryptedComplex128 value
func (s *NullSignedEncryptedComplex128) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	var bin []byte
	s.Valid, err = decryptVerify(value.([]byte), &bin)
	if err != nil {
		return err
	}

	return binary.Read(bytes.NewBuffer(bin), binary.LittleEndian, &s.Raw)
}

// Value converts an initialized NullSignedEncryptedComplex128 value into a value that can safely be stored in the DB
func (s NullSignedEncryptedComplex128) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	var bin bytes.Buffer
	err := binary.Write(&bin, binary.LittleEndian, s.Raw)
	if err != nil {
		return nil, err
	}
	return encryptSign(bin.Bytes())
}
