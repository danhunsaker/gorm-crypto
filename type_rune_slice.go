package gc

import "database/sql/driver"

// EncryptedRuneSlice supports encrypting RuneSlice data
type EncryptedRuneSlice struct {
	Field
	Raw []rune
}

// Scan converts the value from the DB into a usable EncryptedRuneSlice value
func (s *EncryptedRuneSlice) Scan(value interface{}) error {
	return decrypt(value.([]byte), &s.Raw)
}

// Value converts an initialized EncryptedRuneSlice value into a value that can safely be stored in the DB
func (s EncryptedRuneSlice) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

// NullEncryptedRuneSlice supports encrypting nullable RuneSlice data
type NullEncryptedRuneSlice struct {
	Field
	Raw   []rune
	Empty bool
}

// Scan converts the value from the DB into a usable NullEncryptedRuneSlice value
func (s *NullEncryptedRuneSlice) Scan(value interface{}) error {
	if value == nil {
		s.Raw = []rune{}
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), &s.Raw)
}

// Value converts an initialized NullEncryptedRuneSlice value into a value that can safely be stored in the DB
func (s NullEncryptedRuneSlice) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return encrypt(s.Raw)
}

// SignedRuneSlice supports signing RuneSlice data
type SignedRuneSlice struct {
	Field
	Raw   []rune
	Valid bool
}

// Scan converts the value from the DB into a usable SignedRuneSlice value
func (s *SignedRuneSlice) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized SignedRuneSlice value into a value that can safely be stored in the DB
func (s SignedRuneSlice) Value() (driver.Value, error) {
	return sign(s.Raw)
}

// NullSignedRuneSlice supports signing nullable RuneSlice data
type NullSignedRuneSlice struct {
	Field
	Raw   []rune
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedRuneSlice value
func (s *NullSignedRuneSlice) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = []rune{}
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized NullSignedRuneSlice value into a value that can safely be stored in the DB
func (s NullSignedRuneSlice) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return sign(s.Raw)
}

// SignedEncryptedRuneSlice supports signing and encrypting RuneSlice data
type SignedEncryptedRuneSlice struct {
	Field
	Raw   []rune
	Valid bool
}

// Scan converts the value from the DB into a usable SignedEncryptedRuneSlice value
func (s *SignedEncryptedRuneSlice) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized SignedEncryptedRuneSlice value into a value that can safely be stored in the DB
func (s SignedEncryptedRuneSlice) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

// NullSignedEncryptedRuneSlice supports signing and encrypting nullable RuneSlice data
type NullSignedEncryptedRuneSlice struct {
	Field
	Raw   []rune
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedEncryptedRuneSlice value
func (s *NullSignedEncryptedRuneSlice) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = []rune{}
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized NullSignedEncryptedRuneSlice value into a value that can safely be stored in the DB
func (s NullSignedEncryptedRuneSlice) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return encryptSign(s.Raw)
}
