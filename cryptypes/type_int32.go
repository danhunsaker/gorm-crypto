package cryptypes

import "database/sql/driver"

// EncryptedInt32 supports encrypting Int32 data
type EncryptedInt32 struct {
	Field
	Raw int32
}

// Scan converts the value from the DB into a usable EncryptedInt32 value
func (s *EncryptedInt32) Scan(value interface{}) error {
	return decrypt(value.([]byte), &s.Raw)
}

// Value converts an initialized EncryptedInt32 value into a value that can safely be stored in the DB
func (s EncryptedInt32) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

// NullEncryptedInt32 supports encrypting nullable Int32 data
type NullEncryptedInt32 struct {
	Field
	Raw   int32
	Empty bool
}

// Scan converts the value from the DB into a usable NullEncryptedInt32 value
func (s *NullEncryptedInt32) Scan(value interface{}) error {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), &s.Raw)
}

// Value converts an initialized NullEncryptedInt32 value into a value that can safely be stored in the DB
func (s NullEncryptedInt32) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return encrypt(s.Raw)
}

// SignedInt32 supports signing Int32 data
type SignedInt32 struct {
	Field
	Raw   int32
	Valid bool
}

// Scan converts the value from the DB into a usable SignedInt32 value
func (s *SignedInt32) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized SignedInt32 value into a value that can safely be stored in the DB
func (s SignedInt32) Value() (driver.Value, error) {
	return sign(s.Raw)
}

// NullSignedInt32 supports signing nullable Int32 data
type NullSignedInt32 struct {
	Field
	Raw   int32
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedInt32 value
func (s *NullSignedInt32) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized NullSignedInt32 value into a value that can safely be stored in the DB
func (s NullSignedInt32) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return sign(s.Raw)
}

// SignedEncryptedInt32 supports signing and encrypting Int32 data
type SignedEncryptedInt32 struct {
	Field
	Raw   int32
	Valid bool
}

// Scan converts the value from the DB into a usable SignedEncryptedInt32 value
func (s *SignedEncryptedInt32) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized SignedEncryptedInt32 value into a value that can safely be stored in the DB
func (s SignedEncryptedInt32) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

// NullSignedEncryptedInt32 supports signing and encrypting nullable Int32 data
type NullSignedEncryptedInt32 struct {
	Field
	Raw   int32
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedEncryptedInt32 value
func (s *NullSignedEncryptedInt32) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized NullSignedEncryptedInt32 value into a value that can safely be stored in the DB
func (s NullSignedEncryptedInt32) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return encryptSign(s.Raw)
}
