package gc

import "database/sql/driver"

// EncryptedString supports encrypting String data
type EncryptedString struct {
	Field
	Raw string
}

// Scan converts the value from the DB into a usable EncryptedString value
func (s *EncryptedString) Scan(value interface{}) error {
	return decrypt(value.([]byte), &s.Raw)
}

// Value converts an initialized EncryptedString value into a value that can safely be stored in the DB
func (s EncryptedString) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

// NullEncryptedString supports encrypting nullable String data
type NullEncryptedString struct {
	Field
	Raw   string
	Empty bool
}

// Scan converts the value from the DB into a usable NullEncryptedString value
func (s *NullEncryptedString) Scan(value interface{}) error {
	if value == nil {
		s.Raw = ""
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), &s.Raw)
}

// Value converts an initialized NullEncryptedString value into a value that can safely be stored in the DB
func (s NullEncryptedString) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return encrypt(s.Raw)
}

// SignedString supports signing String data
type SignedString struct {
	Field
	Raw   string
	Valid bool
}

// Scan converts the value from the DB into a usable SignedString value
func (s *SignedString) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized SignedString value into a value that can safely be stored in the DB
func (s SignedString) Value() (driver.Value, error) {
	return sign(s.Raw)
}

// NullSignedString supports signing nullable String data
type NullSignedString struct {
	Field
	Raw   string
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedString value
func (s *NullSignedString) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = ""
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized NullSignedString value into a value that can safely be stored in the DB
func (s NullSignedString) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return sign(s.Raw)
}

// SignedEncryptedString supports signing and encrypting String data
type SignedEncryptedString struct {
	Field
	Raw   string
	Valid bool
}

// Scan converts the value from the DB into a usable SignedEncryptedString value
func (s *SignedEncryptedString) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized SignedEncryptedString value into a value that can safely be stored in the DB
func (s SignedEncryptedString) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

// NullSignedEncryptedString supports signing and encrypting nullable String data
type NullSignedEncryptedString struct {
	Field
	Raw   string
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedEncryptedString value
func (s *NullSignedEncryptedString) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = ""
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized NullSignedEncryptedString value into a value that can safely be stored in the DB
func (s NullSignedEncryptedString) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return encryptSign(s.Raw)
}
