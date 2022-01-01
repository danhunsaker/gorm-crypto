package cryptypes

import "database/sql/driver"

// EncryptedByte supports encrypting Byte data
type EncryptedByte struct {
	Field
	Raw byte
}

// Scan converts the value from the DB into a usable EncryptedByte value
func (s *EncryptedByte) Scan(value interface{}) error {
	return decrypt(value.([]byte), &s.Raw)
}

// Value converts an initialized EncryptedByte value into a value that can safely be stored in the DB
func (s EncryptedByte) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

// NullEncryptedByte supports encrypting nullable Byte data
type NullEncryptedByte struct {
	Field
	Raw   byte
	Empty bool
}

// Scan converts the value from the DB into a usable NullEncryptedByte value
func (s *NullEncryptedByte) Scan(value interface{}) error {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), &s.Raw)
}

// Value converts an initialized NullEncryptedByte value into a value that can safely be stored in the DB
func (s NullEncryptedByte) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return encrypt(s.Raw)
}

// SignedByte supports signing Byte data
type SignedByte struct {
	Field
	Raw   byte
	Valid bool
}

// Scan converts the value from the DB into a usable SignedByte value
func (s *SignedByte) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized SignedByte value into a value that can safely be stored in the DB
func (s SignedByte) Value() (driver.Value, error) {
	return sign(s.Raw)
}

// NullSignedByte supports signing nullable Byte data
type NullSignedByte struct {
	Field
	Raw   byte
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedByte value
func (s *NullSignedByte) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized NullSignedByte value into a value that can safely be stored in the DB
func (s NullSignedByte) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return sign(s.Raw)
}

// SignedEncryptedByte supports signing and encrypting Byte data
type SignedEncryptedByte struct {
	Field
	Raw   byte
	Valid bool
}

// Scan converts the value from the DB into a usable SignedEncryptedByte value
func (s *SignedEncryptedByte) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized SignedEncryptedByte value into a value that can safely be stored in the DB
func (s SignedEncryptedByte) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

// NullSignedEncryptedByte supports signing and encrypting nullable Byte data
type NullSignedEncryptedByte struct {
	Field
	Raw   byte
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedEncryptedByte value
func (s *NullSignedEncryptedByte) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized NullSignedEncryptedByte value into a value that can safely be stored in the DB
func (s NullSignedEncryptedByte) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return encryptSign(s.Raw)
}
