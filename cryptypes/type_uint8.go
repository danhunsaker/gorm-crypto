package cryptypes

import "database/sql/driver"

// EncryptedUint8 supports encrypting Uint8 data
type EncryptedUint8 struct {
	Field
	Raw uint8
}

// Scan converts the value from the DB into a usable EncryptedUint8 value
func (s *EncryptedUint8) Scan(value interface{}) error {
	return decrypt(value.([]byte), &s.Raw)
}

// Value converts an initialized EncryptedUint8 value into a value that can safely be stored in the DB
func (s EncryptedUint8) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

// NullEncryptedUint8 supports encrypting nullable Uint8 data
type NullEncryptedUint8 struct {
	Field
	Raw   uint8
	Empty bool
}

// Scan converts the value from the DB into a usable NullEncryptedUint8 value
func (s *NullEncryptedUint8) Scan(value interface{}) error {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), &s.Raw)
}

// Value converts an initialized NullEncryptedUint8 value into a value that can safely be stored in the DB
func (s NullEncryptedUint8) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return encrypt(s.Raw)
}

// SignedUint8 supports signing Uint8 data
type SignedUint8 struct {
	Field
	Raw   uint8
	Valid bool
}

// Scan converts the value from the DB into a usable SignedUint8 value
func (s *SignedUint8) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized SignedUint8 value into a value that can safely be stored in the DB
func (s SignedUint8) Value() (driver.Value, error) {
	return sign(s.Raw)
}

// NullSignedUint8 supports signing nullable Uint8 data
type NullSignedUint8 struct {
	Field
	Raw   uint8
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedUint8 value
func (s *NullSignedUint8) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized NullSignedUint8 value into a value that can safely be stored in the DB
func (s NullSignedUint8) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return sign(s.Raw)
}

// SignedEncryptedUint8 supports signing and encrypting Uint8 data
type SignedEncryptedUint8 struct {
	Field
	Raw   uint8
	Valid bool
}

// Scan converts the value from the DB into a usable SignedEncryptedUint8 value
func (s *SignedEncryptedUint8) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized SignedEncryptedUint8 value into a value that can safely be stored in the DB
func (s SignedEncryptedUint8) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

// NullSignedEncryptedUint8 supports signing and encrypting nullable Uint8 data
type NullSignedEncryptedUint8 struct {
	Field
	Raw   uint8
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedEncryptedUint8 value
func (s *NullSignedEncryptedUint8) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized NullSignedEncryptedUint8 value into a value that can safely be stored in the DB
func (s NullSignedEncryptedUint8) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return encryptSign(s.Raw)
}
