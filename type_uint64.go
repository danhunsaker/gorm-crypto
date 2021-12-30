package gormcrypto

import "database/sql/driver"

// EncryptedUint64 supports encrypting Uint64 data
type EncryptedUint64 struct {
	Field
	Raw uint64
}

// Scan converts the value from the DB into a usable EncryptedUint64 value
func (s *EncryptedUint64) Scan(value interface{}) error {
	return decrypt(value.([]byte), &s.Raw)
}

// Value converts an initialized EncryptedUint64 value into a value that can safely be stored in the DB
func (s EncryptedUint64) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

// NullEncryptedUint64 supports encrypting nullable Uint64 data
type NullEncryptedUint64 struct {
	Field
	Raw   uint64
	Empty bool
}

// Scan converts the value from the DB into a usable NullEncryptedUint64 value
func (s *NullEncryptedUint64) Scan(value interface{}) error {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), &s.Raw)
}

// Value converts an initialized NullEncryptedUint64 value into a value that can safely be stored in the DB
func (s NullEncryptedUint64) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return encrypt(s.Raw)
}

// SignedUint64 supports signing Uint64 data
type SignedUint64 struct {
	Field
	Raw   uint64
	Valid bool
}

// Scan converts the value from the DB into a usable SignedUint64 value
func (s *SignedUint64) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized SignedUint64 value into a value that can safely be stored in the DB
func (s SignedUint64) Value() (driver.Value, error) {
	return sign(s.Raw)
}

// NullSignedUint64 supports signing nullable Uint64 data
type NullSignedUint64 struct {
	Field
	Raw   uint64
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedUint64 value
func (s *NullSignedUint64) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized NullSignedUint64 value into a value that can safely be stored in the DB
func (s NullSignedUint64) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return sign(s.Raw)
}

// SignedEncryptedUint64 supports signing and encrypting Uint64 data
type SignedEncryptedUint64 struct {
	Field
	Raw   uint64
	Valid bool
}

// Scan converts the value from the DB into a usable SignedEncryptedUint64 value
func (s *SignedEncryptedUint64) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized SignedEncryptedUint64 value into a value that can safely be stored in the DB
func (s SignedEncryptedUint64) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

// NullSignedEncryptedUint64 supports signing and encrypting nullable Uint64 data
type NullSignedEncryptedUint64 struct {
	Field
	Raw   uint64
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedEncryptedUint64 value
func (s *NullSignedEncryptedUint64) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized NullSignedEncryptedUint64 value into a value that can safely be stored in the DB
func (s NullSignedEncryptedUint64) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return encryptSign(s.Raw)
}
