package gc

import "database/sql/driver"

// EncryptedUint supports encrypting Uint data
type EncryptedUint struct {
	Field
	Raw uint
}

// Scan converts the value from the DB into a usable EncryptedUint value
func (s *EncryptedUint) Scan(value interface{}) error {
	return decrypt(value.([]byte), &s.Raw)
}

// Value converts an initialized EncryptedUint value into a value that can safely be stored in the DB
func (s EncryptedUint) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

// NullEncryptedUint supports encrypting nullable Uint data
type NullEncryptedUint struct {
	Field
	Raw   uint
	Empty bool
}

// Scan converts the value from the DB into a usable NullEncryptedUint value
func (s *NullEncryptedUint) Scan(value interface{}) error {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), &s.Raw)
}

// Value converts an initialized NullEncryptedUint value into a value that can safely be stored in the DB
func (s NullEncryptedUint) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return encrypt(s.Raw)
}

// SignedUint supports signing Uint data
type SignedUint struct {
	Field
	Raw   uint
	Valid bool
}

// Scan converts the value from the DB into a usable SignedUint value
func (s *SignedUint) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized SignedUint value into a value that can safely be stored in the DB
func (s SignedUint) Value() (driver.Value, error) {
	return sign(s.Raw)
}

// NullSignedUint supports signing nullable Uint data
type NullSignedUint struct {
	Field
	Raw   uint
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedUint value
func (s *NullSignedUint) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized NullSignedUint value into a value that can safely be stored in the DB
func (s NullSignedUint) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return sign(s.Raw)
}

// SignedEncryptedUint supports signing and encrypting Uint data
type SignedEncryptedUint struct {
	Field
	Raw   uint
	Valid bool
}

// Scan converts the value from the DB into a usable SignedEncryptedUint value
func (s *SignedEncryptedUint) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized SignedEncryptedUint value into a value that can safely be stored in the DB
func (s SignedEncryptedUint) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

// NullSignedEncryptedUint supports signing and encrypting nullable Uint data
type NullSignedEncryptedUint struct {
	Field
	Raw   uint
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedEncryptedUint value
func (s *NullSignedEncryptedUint) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized NullSignedEncryptedUint value into a value that can safely be stored in the DB
func (s NullSignedEncryptedUint) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return encryptSign(s.Raw)
}
