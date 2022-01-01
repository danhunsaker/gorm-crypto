package cryptypes

import "database/sql/driver"

// EncryptedFloat64 supports encrypting Float64 data
type EncryptedFloat64 struct {
	Field
	Raw float64
}

// Scan converts the value from the DB into a usable EncryptedFloat64 value
func (s *EncryptedFloat64) Scan(value interface{}) error {
	return decrypt(value.([]byte), &s.Raw)
}

// Value converts an initialized EncryptedFloat64 value into a value that can safely be stored in the DB
func (s EncryptedFloat64) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

// NullEncryptedFloat64 supports encrypting nullable Float64 data
type NullEncryptedFloat64 struct {
	Field
	Raw   float64
	Empty bool
}

// Scan converts the value from the DB into a usable NullEncryptedFloat64 value
func (s *NullEncryptedFloat64) Scan(value interface{}) error {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), &s.Raw)
}

// Value converts an initialized NullEncryptedFloat64 value into a value that can safely be stored in the DB
func (s NullEncryptedFloat64) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return encrypt(s.Raw)
}

// SignedFloat64 supports signing Float64 data
type SignedFloat64 struct {
	Field
	Raw   float64
	Valid bool
}

// Scan converts the value from the DB into a usable SignedFloat64 value
func (s *SignedFloat64) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized SignedFloat64 value into a value that can safely be stored in the DB
func (s SignedFloat64) Value() (driver.Value, error) {
	return sign(s.Raw)
}

// NullSignedFloat64 supports signing nullable Float64 data
type NullSignedFloat64 struct {
	Field
	Raw   float64
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedFloat64 value
func (s *NullSignedFloat64) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized NullSignedFloat64 value into a value that can safely be stored in the DB
func (s NullSignedFloat64) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return sign(s.Raw)
}

// SignedEncryptedFloat64 supports signing and encrypting Float64 data
type SignedEncryptedFloat64 struct {
	Field
	Raw   float64
	Valid bool
}

// Scan converts the value from the DB into a usable SignedEncryptedFloat64 value
func (s *SignedEncryptedFloat64) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized SignedEncryptedFloat64 value into a value that can safely be stored in the DB
func (s SignedEncryptedFloat64) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

// NullSignedEncryptedFloat64 supports signing and encrypting nullable Float64 data
type NullSignedEncryptedFloat64 struct {
	Field
	Raw   float64
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedEncryptedFloat64 value
func (s *NullSignedEncryptedFloat64) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized NullSignedEncryptedFloat64 value into a value that can safely be stored in the DB
func (s NullSignedEncryptedFloat64) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return encryptSign(s.Raw)
}
