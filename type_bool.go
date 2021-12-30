package gormcrypto

import "database/sql/driver"

// EncryptedBool supports encrypting Bool data
type EncryptedBool struct {
	Field
	Raw bool
}

// Scan converts the value from the DB into a usable EncryptedBool value
func (s *EncryptedBool) Scan(value interface{}) error {
	return decrypt(value.([]byte), &s.Raw)
}

// Value converts an initialized EncryptedBool value into a value that can safely be stored in the DB
func (s EncryptedBool) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

// NullEncryptedBool supports encrypting nullable Bool data
type NullEncryptedBool struct {
	Field
	Raw   bool
	Empty bool
}

// Scan converts the value from the DB into a usable NullEncryptedBool value
func (s *NullEncryptedBool) Scan(value interface{}) error {
	if value == nil {
		s.Raw = false
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), &s.Raw)
}

// Value converts an initialized NullEncryptedBool value into a value that can safely be stored in the DB
func (s NullEncryptedBool) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return encrypt(s.Raw)
}

// SignedBool supports signing Bool data
type SignedBool struct {
	Field
	Raw   bool
	Valid bool
}

// Scan converts the value from the DB into a usable SignedBool value
func (s *SignedBool) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized SignedBool value into a value that can safely be stored in the DB
func (s SignedBool) Value() (driver.Value, error) {
	return sign(s.Raw)
}

// NullSignedBool supports signing nullable Bool data
type NullSignedBool struct {
	Field
	Raw   bool
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedBool value
func (s *NullSignedBool) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = false
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized NullSignedBool value into a value that can safely be stored in the DB
func (s NullSignedBool) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return sign(s.Raw)
}

// SignedEncryptedBool supports signing and encrypting Bool data
type SignedEncryptedBool struct {
	Field
	Raw   bool
	Valid bool
}

// Scan converts the value from the DB into a usable SignedEncryptedBool value
func (s *SignedEncryptedBool) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized SignedEncryptedBool value into a value that can safely be stored in the DB
func (s SignedEncryptedBool) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

// NullSignedEncryptedBool supports signing and encrypting nullable Bool data
type NullSignedEncryptedBool struct {
	Field
	Raw   bool
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedEncryptedBool value
func (s *NullSignedEncryptedBool) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = false
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized NullSignedEncryptedBool value into a value that can safely be stored in the DB
func (s NullSignedEncryptedBool) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return encryptSign(s.Raw)
}
