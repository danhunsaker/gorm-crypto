package gormcrypto

import "database/sql/driver"

// EncryptedInt16 supports encrypting Int16 data
type EncryptedInt16 struct {
	Field
	Raw int16
}

// Scan converts the value from the DB into a usable EncryptedInt16 value
func (s *EncryptedInt16) Scan(value interface{}) error {
	return decrypt(value.([]byte), &s.Raw)
}

// Value converts an initialized EncryptedInt16 value into a value that can safely be stored in the DB
func (s EncryptedInt16) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

// NullEncryptedInt16 supports encrypting nullable Int16 data
type NullEncryptedInt16 struct {
	Field
	Raw   int16
	Empty bool
}

// Scan converts the value from the DB into a usable NullEncryptedInt16 value
func (s *NullEncryptedInt16) Scan(value interface{}) error {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), &s.Raw)
}

// Value converts an initialized NullEncryptedInt16 value into a value that can safely be stored in the DB
func (s NullEncryptedInt16) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return encrypt(s.Raw)
}

// SignedInt16 supports signing Int16 data
type SignedInt16 struct {
	Field
	Raw   int16
	Valid bool
}

// Scan converts the value from the DB into a usable SignedInt16 value
func (s *SignedInt16) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized SignedInt16 value into a value that can safely be stored in the DB
func (s SignedInt16) Value() (driver.Value, error) {
	return sign(s.Raw)
}

// NullSignedInt16 supports signing nullable Int16 data
type NullSignedInt16 struct {
	Field
	Raw   int16
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedInt16 value
func (s *NullSignedInt16) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized NullSignedInt16 value into a value that can safely be stored in the DB
func (s NullSignedInt16) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return sign(s.Raw)
}

// SignedEncryptedInt16 supports signing and encrypting Int16 data
type SignedEncryptedInt16 struct {
	Field
	Raw   int16
	Valid bool
}

// Scan converts the value from the DB into a usable SignedEncryptedInt16 value
func (s *SignedEncryptedInt16) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized SignedEncryptedInt16 value into a value that can safely be stored in the DB
func (s SignedEncryptedInt16) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

// NullSignedEncryptedInt16 supports signing and encrypting nullable Int16 data
type NullSignedEncryptedInt16 struct {
	Field
	Raw   int16
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedEncryptedInt16 value
func (s *NullSignedEncryptedInt16) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized NullSignedEncryptedInt16 value into a value that can safely be stored in the DB
func (s NullSignedEncryptedInt16) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return encryptSign(s.Raw)
}
