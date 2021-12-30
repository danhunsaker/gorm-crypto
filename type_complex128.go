package gorm_crypto

import (
	"bytes"
	"database/sql/driver"
	"encoding/binary"
)

type EncryptedComplex128 struct {
	Field
	Raw complex128
}

func (s *EncryptedComplex128) Scan(value interface{}) error {
	var bin []byte
	err := decrypt(value.([]byte), &bin)
	if err != nil {
		return err
	}

	return binary.Read(bytes.NewBuffer(bin), binary.LittleEndian, &s.Raw)
}

func (s EncryptedComplex128) Value() (driver.Value, error) {
	var bin bytes.Buffer
	err := binary.Write(&bin, binary.LittleEndian, s.Raw)
	if err != nil {
		return nil, err
	}
	return encrypt(bin.Bytes())
}

type NullEncryptedComplex128 struct {
	Field
	Raw   complex128
	Empty bool
}

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

func (s NullEncryptedComplex128) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		var bin bytes.Buffer
		err := binary.Write(&bin, binary.LittleEndian, s.Raw)
		if err != nil {
			return nil, err
		}
		return encrypt(bin.Bytes())
	}
}

type SignedComplex128 struct {
	Field
	Raw   complex128
	Valid bool
}

func (s *SignedComplex128) Scan(value interface{}) (err error) {
	var bin []byte
	s.Valid, err = verify(value.([]byte), &bin)
	if err != nil {
		return err
	}

	return binary.Read(bytes.NewBuffer(bin), binary.LittleEndian, &s.Raw)
}

func (s SignedComplex128) Value() (driver.Value, error) {
	var bin bytes.Buffer
	err := binary.Write(&bin, binary.LittleEndian, s.Raw)
	if err != nil {
		return nil, err
	}
	return sign(bin.Bytes())
}

type NullSignedComplex128 struct {
	Field
	Raw   complex128
	Empty bool
	Valid bool
}

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

func (s NullSignedComplex128) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		var bin bytes.Buffer
		err := binary.Write(&bin, binary.LittleEndian, s.Raw)
		if err != nil {
			return nil, err
		}
		return sign(bin.Bytes())
	}
}

type SignedEncryptedComplex128 struct {
	Field
	Raw   complex128
	Valid bool
}

func (s *SignedEncryptedComplex128) Scan(value interface{}) (err error) {
	var bin []byte
	s.Valid, err = decryptVerify(value.([]byte), &bin)
	if err != nil {
		return err
	}

	return binary.Read(bytes.NewBuffer(bin), binary.LittleEndian, &s.Raw)
}

func (s SignedEncryptedComplex128) Value() (driver.Value, error) {
	var bin bytes.Buffer
	err := binary.Write(&bin, binary.LittleEndian, s.Raw)
	if err != nil {
		return nil, err
	}
	return encryptSign(bin.Bytes())
}

type NullSignedEncryptedComplex128 struct {
	Field
	Raw   complex128
	Empty bool
	Valid bool
}

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

func (s NullSignedEncryptedComplex128) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	} else {
		var bin bytes.Buffer
		err := binary.Write(&bin, binary.LittleEndian, s.Raw)
		if err != nil {
			return nil, err
		}
		return encryptSign(bin.Bytes())
	}
}
