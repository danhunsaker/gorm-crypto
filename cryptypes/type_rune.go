package cryptypes

import "database/sql/driver"

// EncryptedRune supports encrypting Rune data
type EncryptedRune struct {
	Field
	Raw rune
}

// Scan converts the value from the DB into a usable EncryptedRune value
func (s *EncryptedRune) Scan(value interface{}) error {
	return decrypt(value.([]byte), &s.Raw)
}

// Value converts an initialized EncryptedRune value into a value that can safely be stored in the DB
func (s EncryptedRune) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

// NullEncryptedRune supports encrypting nullable Rune data
type NullEncryptedRune struct {
	Field
	Raw   rune
	Empty bool
}

// Scan converts the value from the DB into a usable NullEncryptedRune value
func (s *NullEncryptedRune) Scan(value interface{}) error {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), &s.Raw)
}

// Value converts an initialized NullEncryptedRune value into a value that can safely be stored in the DB
func (s NullEncryptedRune) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return encrypt(s.Raw)
}

// SignedRune supports signing Rune data
type SignedRune struct {
	Field
	Raw   rune
	Valid bool
}

// Scan converts the value from the DB into a usable SignedRune value
func (s *SignedRune) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized SignedRune value into a value that can safely be stored in the DB
func (s SignedRune) Value() (driver.Value, error) {
	return sign(s.Raw)
}

// NullSignedRune supports signing nullable Rune data
type NullSignedRune struct {
	Field
	Raw   rune
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedRune value
func (s *NullSignedRune) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized NullSignedRune value into a value that can safely be stored in the DB
func (s NullSignedRune) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return sign(s.Raw)
}

// SignedEncryptedRune supports signing and encrypting Rune data
type SignedEncryptedRune struct {
	Field
	Raw   rune
	Valid bool
}

// Scan converts the value from the DB into a usable SignedEncryptedRune value
func (s *SignedEncryptedRune) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized SignedEncryptedRune value into a value that can safely be stored in the DB
func (s SignedEncryptedRune) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

// NullSignedEncryptedRune supports signing and encrypting nullable Rune data
type NullSignedEncryptedRune struct {
	Field
	Raw   rune
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedEncryptedRune value
func (s *NullSignedEncryptedRune) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized NullSignedEncryptedRune value into a value that can safely be stored in the DB
func (s NullSignedEncryptedRune) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return encryptSign(s.Raw)
}
