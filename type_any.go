package gc

import "database/sql/driver"

// EncryptedAny supports encrypting Any data
type EncryptedAny struct {
	Field
	Raw interface{}
}

// Scan converts the value from the DB into a usable EncryptedAny value
func (s *EncryptedAny) Scan(value interface{}) error {
	return decrypt(value.([]byte), &s.Raw)
}

// Value converts an initialized EncryptedAny value into a value that can safely be stored in the DB
func (s EncryptedAny) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

// NullEncryptedAny supports encrypting nullable Any data
type NullEncryptedAny struct {
	Field
	Raw   interface{}
	Empty bool
}

// Scan converts the value from the DB into a usable NullEncryptedAny value
func (s *NullEncryptedAny) Scan(value interface{}) error {
	if value == nil {
		s.Raw = nil
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), &s.Raw)
}

// Value converts an initialized NullEncryptedAny value into a value that can safely be stored in the DB
func (s NullEncryptedAny) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return encrypt(s.Raw)
}

// SignedAny supports signing Any data
type SignedAny struct {
	Field
	Raw   interface{}
	Valid bool
}

// Scan converts the value from the DB into a usable SignedAny value
func (s *SignedAny) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized SignedAny value into a value that can safely be stored in the DB
func (s SignedAny) Value() (driver.Value, error) {
	return sign(s.Raw)
}

// NullSignedAny supports signing nullable Any data
type NullSignedAny struct {
	Field
	Raw   interface{}
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedAny value
func (s *NullSignedAny) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = nil
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized NullSignedAny value into a value that can safely be stored in the DB
func (s NullSignedAny) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return sign(s.Raw)
}

// SignedEncryptedAny supports signing and encrypting Any data
type SignedEncryptedAny struct {
	Field
	Raw   interface{}
	Valid bool
}

// Scan converts the value from the DB into a usable SignedEncryptedAny value
func (s *SignedEncryptedAny) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized SignedEncryptedAny value into a value that can safely be stored in the DB
func (s SignedEncryptedAny) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

// NullSignedEncryptedAny supports signing and encrypting nullable Any data
type NullSignedEncryptedAny struct {
	Field
	Raw   interface{}
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedEncryptedAny value
func (s *NullSignedEncryptedAny) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = nil
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized NullSignedEncryptedAny value into a value that can safely be stored in the DB
func (s NullSignedEncryptedAny) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return encryptSign(s.Raw)
}
