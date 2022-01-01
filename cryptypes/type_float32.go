package cryptypes

import "database/sql/driver"

// EncryptedFloat32 supports encrypting Float32 data
type EncryptedFloat32 struct {
	Field
	Raw float32
}

// Scan converts the value from the DB into a usable EncryptedFloat32 value
func (s *EncryptedFloat32) Scan(value interface{}) error {
	return decrypt(value.([]byte), &s.Raw)
}

// Value converts an initialized EncryptedFloat32 value into a value that can safely be stored in the DB
func (s EncryptedFloat32) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

// NullEncryptedFloat32 supports encrypting nullable Float32 data
type NullEncryptedFloat32 struct {
	Field
	Raw   float32
	Empty bool
}

// Scan converts the value from the DB into a usable NullEncryptedFloat32 value
func (s *NullEncryptedFloat32) Scan(value interface{}) error {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), &s.Raw)
}

// Value converts an initialized NullEncryptedFloat32 value into a value that can safely be stored in the DB
func (s NullEncryptedFloat32) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return encrypt(s.Raw)
}

// SignedFloat32 supports signing Float32 data
type SignedFloat32 struct {
	Field
	Raw   float32
	Valid bool
}

// Scan converts the value from the DB into a usable SignedFloat32 value
func (s *SignedFloat32) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized SignedFloat32 value into a value that can safely be stored in the DB
func (s SignedFloat32) Value() (driver.Value, error) {
	return sign(s.Raw)
}

// NullSignedFloat32 supports signing nullable Float32 data
type NullSignedFloat32 struct {
	Field
	Raw   float32
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedFloat32 value
func (s *NullSignedFloat32) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized NullSignedFloat32 value into a value that can safely be stored in the DB
func (s NullSignedFloat32) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return sign(s.Raw)
}

// SignedEncryptedFloat32 supports signing and encrypting Float32 data
type SignedEncryptedFloat32 struct {
	Field
	Raw   float32
	Valid bool
}

// Scan converts the value from the DB into a usable SignedEncryptedFloat32 value
func (s *SignedEncryptedFloat32) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized SignedEncryptedFloat32 value into a value that can safely be stored in the DB
func (s SignedEncryptedFloat32) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

// NullSignedEncryptedFloat32 supports signing and encrypting nullable Float32 data
type NullSignedEncryptedFloat32 struct {
	Field
	Raw   float32
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedEncryptedFloat32 value
func (s *NullSignedEncryptedFloat32) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized NullSignedEncryptedFloat32 value into a value that can safely be stored in the DB
func (s NullSignedEncryptedFloat32) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return encryptSign(s.Raw)
}
