package gorm_crypto

import (
	"bytes"
	"database/sql/driver"
	"encoding/binary"
)

type EncryptedComplex64 struct {
	Field
	Raw complex64
}

func (s *EncryptedComplex64) Scan(value interface{}) error {
	var bin []byte
	err := decrypt(value.([]byte), &bin)
	if err != nil {
		return err
	}

	return binary.Read(bytes.NewBuffer(bin), binary.LittleEndian, &s.Raw)
}

func (s EncryptedComplex64) Value() (driver.Value, error) {
	var bin bytes.Buffer
	err := binary.Write(&bin, binary.LittleEndian, s.Raw)
	if err != nil {
		return nil, err
	}
	return encrypt(bin.Bytes())
}

type NullEncryptedComplex64 struct {
	Field
	Raw   complex64
	Empty bool
}

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

func (s NullEncryptedComplex64) Value() (driver.Value, error) {
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

type SignedComplex64 struct {
	Field
	Raw   complex64
	Valid bool
}

func (s *SignedComplex64) Scan(value interface{}) (err error) {
	var bin []byte
	s.Valid, err = verify(value.([]byte), &bin)
	if err != nil {
		return err
	}

	return binary.Read(bytes.NewBuffer(bin), binary.LittleEndian, &s.Raw)
}

func (s SignedComplex64) Value() (driver.Value, error) {
	var bin bytes.Buffer
	err := binary.Write(&bin, binary.LittleEndian, s.Raw)
	if err != nil {
		return nil, err
	}
	return sign(bin.Bytes())
}

type NullSignedComplex64 struct {
	Field
	Raw   complex64
	Empty bool
	Valid bool
}

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

func (s NullSignedComplex64) Value() (driver.Value, error) {
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

type SignedEncryptedComplex64 struct {
	Field
	Raw   complex64
	Valid bool
}

func (s *SignedEncryptedComplex64) Scan(value interface{}) (err error) {
	var bin []byte
	s.Valid, err = decryptVerify(value.([]byte), &bin)
	if err != nil {
		return err
	}

	return binary.Read(bytes.NewBuffer(bin), binary.LittleEndian, &s.Raw)
}

func (s SignedEncryptedComplex64) Value() (driver.Value, error) {
	var bin bytes.Buffer
	err := binary.Write(&bin, binary.LittleEndian, s.Raw)
	if err != nil {
		return nil, err
	}
	return encryptSign(bin.Bytes())
}

type NullSignedEncryptedComplex64 struct {
	Field
	Raw   complex64
	Empty bool
	Valid bool
}

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

func (s NullSignedEncryptedComplex64) Value() (driver.Value, error) {
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
