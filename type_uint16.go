package gormcrypto

import "database/sql/driver"

// EncryptedUint16 supports encrypting Uint16 data
type EncryptedUint16 struct {
	Field
	Raw uint16
}

// Scan converts the value from the DB into a usable EncryptedUint16 value
func (s *EncryptedUint16) Scan(value interface{}) error {
	return decrypt(value.([]byte), &s.Raw)
}

// Value converts an initialized EncryptedUint16 value into a value that can safely be stored in the DB
func (s EncryptedUint16) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

// NullEncryptedUint16 supports encrypting nullable Uint16 data
type NullEncryptedUint16 struct {
	Field
	Raw   uint16
	Empty bool
}

// Scan converts the value from the DB into a usable NullEncryptedUint16 value
func (s *NullEncryptedUint16) Scan(value interface{}) error {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), &s.Raw)
}

// Value converts an initialized NullEncryptedUint16 value into a value that can safely be stored in the DB
func (s NullEncryptedUint16) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return encrypt(s.Raw)
}

// SignedUint16 supports signing Uint16 data
type SignedUint16 struct {
	Field
	Raw   uint16
	Valid bool
}

// Scan converts the value from the DB into a usable SignedUint16 value
func (s *SignedUint16) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized SignedUint16 value into a value that can safely be stored in the DB
func (s SignedUint16) Value() (driver.Value, error) {
	return sign(s.Raw)
}

// NullSignedUint16 supports signing nullable Uint16 data
type NullSignedUint16 struct {
	Field
	Raw   uint16
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedUint16 value
func (s *NullSignedUint16) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized NullSignedUint16 value into a value that can safely be stored in the DB
func (s NullSignedUint16) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return sign(s.Raw)
}

// SignedEncryptedUint16 supports signing and encrypting Uint16 data
type SignedEncryptedUint16 struct {
	Field
	Raw   uint16
	Valid bool
}

// Scan converts the value from the DB into a usable SignedEncryptedUint16 value
func (s *SignedEncryptedUint16) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized SignedEncryptedUint16 value into a value that can safely be stored in the DB
func (s SignedEncryptedUint16) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

// NullSignedEncryptedUint16 supports signing and encrypting nullable Uint16 data
type NullSignedEncryptedUint16 struct {
	Field
	Raw   uint16
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedEncryptedUint16 value
func (s *NullSignedEncryptedUint16) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized NullSignedEncryptedUint16 value into a value that can safely be stored in the DB
func (s NullSignedEncryptedUint16) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return encryptSign(s.Raw)
}
