package gormcrypto

import (
	"bytes"
	"database/sql/driver"
	"encoding/binary"
)

// EncryptedComplex64 supports encrypting Complex64 data
type EncryptedComplex64 struct {
	Field
	Raw complex64
}

// Scan converts the value from the DB into a usable EncryptedComplex64 value
func (s *EncryptedComplex64) Scan(value interface{}) error {
	var bin []byte
	err := decrypt(value.([]byte), &bin)
	if err != nil {
		return err
	}

	return binary.Read(bytes.NewBuffer(bin), binary.LittleEndian, &s.Raw)
}

// Value converts an initialized EncryptedComplex64 value into a value that can safely be stored in the DB
func (s EncryptedComplex64) Value() (driver.Value, error) {
	var bin bytes.Buffer
	err := binary.Write(&bin, binary.LittleEndian, s.Raw)
	if err != nil {
		return nil, err
	}
	return encrypt(bin.Bytes())
}

// NullEncryptedComplex64 supports encrypting nullable Complex64 data
type NullEncryptedComplex64 struct {
	Field
	Raw   complex64
	Empty bool
}

// Scan converts the value from the DB into a usable NullEncryptedComplex64 value
func (s *NullEncryptedComplex64) Scan(value interface{}) error {
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

// Value converts an initialized NullEncryptedComplex64 value into a value that can safely be stored in the DB
func (s NullEncryptedComplex64) Value() (driver.Value, error) {
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

// SignedComplex64 supports signing Complex64 data
type SignedComplex64 struct {
	Field
	Raw   complex64
	Valid bool
}

// Scan converts the value from the DB into a usable SignedComplex64 value
func (s *SignedComplex64) Scan(value interface{}) (err error) {
	var bin []byte
	s.Valid, err = verify(value.([]byte), &bin)
	if err != nil {
		return err
	}

	return binary.Read(bytes.NewBuffer(bin), binary.LittleEndian, &s.Raw)
}

// Value converts an initialized SignedComplex64 value into a value that can safely be stored in the DB
func (s SignedComplex64) Value() (driver.Value, error) {
	var bin bytes.Buffer
	err := binary.Write(&bin, binary.LittleEndian, s.Raw)
	if err != nil {
		return nil, err
	}
	return sign(bin.Bytes())
}

// NullSignedComplex64 supports signing nullable Complex64 data
type NullSignedComplex64 struct {
	Field
	Raw   complex64
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedComplex64 value
func (s *NullSignedComplex64) Scan(value interface{}) (err error) {
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

// Value converts an initialized NullSignedComplex64 value into a value that can safely be stored in the DB
func (s NullSignedComplex64) Value() (driver.Value, error) {
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

// SignedEncryptedComplex64 supports signing and encrypting Complex64 data
type SignedEncryptedComplex64 struct {
	Field
	Raw   complex64
	Valid bool
}

// Scan converts the value from the DB into a usable SignedEncryptedComplex64 value
func (s *SignedEncryptedComplex64) Scan(value interface{}) (err error) {
	var bin []byte
	s.Valid, err = decryptVerify(value.([]byte), &bin)
	if err != nil {
		return err
	}

	return binary.Read(bytes.NewBuffer(bin), binary.LittleEndian, &s.Raw)
}

// Value converts an initialized SignedEncryptedComplex64 value into a value that can safely be stored in the DB
func (s SignedEncryptedComplex64) Value() (driver.Value, error) {
	var bin bytes.Buffer
	err := binary.Write(&bin, binary.LittleEndian, s.Raw)
	if err != nil {
		return nil, err
	}
	return encryptSign(bin.Bytes())
}

// NullSignedEncryptedComplex64 supports signing and encrypting nullable Complex64 data
type NullSignedEncryptedComplex64 struct {
	Field
	Raw   complex64
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedEncryptedComplex64 value
func (s *NullSignedEncryptedComplex64) Scan(value interface{}) (err error) {
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

// Value converts an initialized NullSignedEncryptedComplex64 value into a value that can safely be stored in the DB
func (s NullSignedEncryptedComplex64) Value() (driver.Value, error) {
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
