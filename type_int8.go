package gormcrypto

import "database/sql/driver"

// EncryptedInt8 supports encrypting Int8 data
type EncryptedInt8 struct {
	Field
	Raw int8
}

// Scan converts the value from the DB into a usable EncryptedInt8 value
func (s *EncryptedInt8) Scan(value interface{}) error {
	return decrypt(value.([]byte), &s.Raw)
}

// Value converts an initialized EncryptedInt8 value into a value that can safely be stored in the DB
func (s EncryptedInt8) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

// NullEncryptedInt8 supports encrypting nullable Int8 data
type NullEncryptedInt8 struct {
	Field
	Raw   int8
	Empty bool
}

// Scan converts the value from the DB into a usable NullEncryptedInt8 value
func (s *NullEncryptedInt8) Scan(value interface{}) error {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), &s.Raw)
}

// Value converts an initialized NullEncryptedInt8 value into a value that can safely be stored in the DB
func (s NullEncryptedInt8) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return encrypt(s.Raw)
}

// SignedInt8 supports signing Int8 data
type SignedInt8 struct {
	Field
	Raw   int8
	Valid bool
}

// Scan converts the value from the DB into a usable SignedInt8 value
func (s *SignedInt8) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized SignedInt8 value into a value that can safely be stored in the DB
func (s SignedInt8) Value() (driver.Value, error) {
	return sign(s.Raw)
}

// NullSignedInt8 supports signing nullable Int8 data
type NullSignedInt8 struct {
	Field
	Raw   int8
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedInt8 value
func (s *NullSignedInt8) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized NullSignedInt8 value into a value that can safely be stored in the DB
func (s NullSignedInt8) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return sign(s.Raw)
}

// SignedEncryptedInt8 supports signing and encrypting Int8 data
type SignedEncryptedInt8 struct {
	Field
	Raw   int8
	Valid bool
}

// Scan converts the value from the DB into a usable SignedEncryptedInt8 value
func (s *SignedEncryptedInt8) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized SignedEncryptedInt8 value into a value that can safely be stored in the DB
func (s SignedEncryptedInt8) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

// NullSignedEncryptedInt8 supports signing and encrypting nullable Int8 data
type NullSignedEncryptedInt8 struct {
	Field
	Raw   int8
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedEncryptedInt8 value
func (s *NullSignedEncryptedInt8) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized NullSignedEncryptedInt8 value into a value that can safely be stored in the DB
func (s NullSignedEncryptedInt8) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return encryptSign(s.Raw)
}
