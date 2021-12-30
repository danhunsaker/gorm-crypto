package gormcrypto

import "database/sql/driver"

// EncryptedInt supports encrypting Int data
type EncryptedInt struct {
	Field
	Raw int
}

// Scan converts the value from the DB into a usable EncryptedInt value
func (s *EncryptedInt) Scan(value interface{}) error {
	return decrypt(value.([]byte), &s.Raw)
}

// Value converts an initialized EncryptedInt value into a value that can safely be stored in the DB
func (s EncryptedInt) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

// NullEncryptedInt supports encrypting nullable Int data
type NullEncryptedInt struct {
	Field
	Raw   int
	Empty bool
}

// Scan converts the value from the DB into a usable NullEncryptedInt value
func (s *NullEncryptedInt) Scan(value interface{}) error {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), &s.Raw)
}

// Value converts an initialized NullEncryptedInt value into a value that can safely be stored in the DB
func (s NullEncryptedInt) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return encrypt(s.Raw)
}

// SignedInt supports signing Int data
type SignedInt struct {
	Field
	Raw   int
	Valid bool
}

// Scan converts the value from the DB into a usable SignedInt value
func (s *SignedInt) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized SignedInt value into a value that can safely be stored in the DB
func (s SignedInt) Value() (driver.Value, error) {
	return sign(s.Raw)
}

// NullSignedInt supports signing nullable Int data
type NullSignedInt struct {
	Field
	Raw   int
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedInt value
func (s *NullSignedInt) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized NullSignedInt value into a value that can safely be stored in the DB
func (s NullSignedInt) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return sign(s.Raw)
}

// SignedEncryptedInt supports signing and encrypting Int data
type SignedEncryptedInt struct {
	Field
	Raw   int
	Valid bool
}

// Scan converts the value from the DB into a usable SignedEncryptedInt value
func (s *SignedEncryptedInt) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized SignedEncryptedInt value into a value that can safely be stored in the DB
func (s SignedEncryptedInt) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

// NullSignedEncryptedInt supports signing and encrypting nullable Int data
type NullSignedEncryptedInt struct {
	Field
	Raw   int
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedEncryptedInt value
func (s *NullSignedEncryptedInt) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized NullSignedEncryptedInt value into a value that can safely be stored in the DB
func (s NullSignedEncryptedInt) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return encryptSign(s.Raw)
}
