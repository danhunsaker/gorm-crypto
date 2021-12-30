package gormcrypto

import "database/sql/driver"

// EncryptedUint32 supports encrypting Uint32 data
type EncryptedUint32 struct {
	Field
	Raw uint32
}

// Scan converts the value from the DB into a usable EncryptedUint32 value
func (s *EncryptedUint32) Scan(value interface{}) error {
	return decrypt(value.([]byte), &s.Raw)
}

// Value converts an initialized EncryptedUint32 value into a value that can safely be stored in the DB
func (s EncryptedUint32) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

// NullEncryptedUint32 supports encrypting nullable Uint32 data
type NullEncryptedUint32 struct {
	Field
	Raw   uint32
	Empty bool
}

// Scan converts the value from the DB into a usable NullEncryptedUint32 value
func (s *NullEncryptedUint32) Scan(value interface{}) error {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), &s.Raw)
}

// Value converts an initialized NullEncryptedUint32 value into a value that can safely be stored in the DB
func (s NullEncryptedUint32) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return encrypt(s.Raw)
}

// SignedUint32 supports signing Uint32 data
type SignedUint32 struct {
	Field
	Raw   uint32
	Valid bool
}

// Scan converts the value from the DB into a usable SignedUint32 value
func (s *SignedUint32) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized SignedUint32 value into a value that can safely be stored in the DB
func (s SignedUint32) Value() (driver.Value, error) {
	return sign(s.Raw)
}

// NullSignedUint32 supports signing nullable Uint32 data
type NullSignedUint32 struct {
	Field
	Raw   uint32
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedUint32 value
func (s *NullSignedUint32) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized NullSignedUint32 value into a value that can safely be stored in the DB
func (s NullSignedUint32) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return sign(s.Raw)
}

// SignedEncryptedUint32 supports signing and encrypting Uint32 data
type SignedEncryptedUint32 struct {
	Field
	Raw   uint32
	Valid bool
}

// Scan converts the value from the DB into a usable SignedEncryptedUint32 value
func (s *SignedEncryptedUint32) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized SignedEncryptedUint32 value into a value that can safely be stored in the DB
func (s SignedEncryptedUint32) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

// NullSignedEncryptedUint32 supports signing and encrypting nullable Uint32 data
type NullSignedEncryptedUint32 struct {
	Field
	Raw   uint32
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedEncryptedUint32 value
func (s *NullSignedEncryptedUint32) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized NullSignedEncryptedUint32 value into a value that can safely be stored in the DB
func (s NullSignedEncryptedUint32) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return encryptSign(s.Raw)
}
