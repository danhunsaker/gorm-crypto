package gc

import "database/sql/driver"

// EncryptedInt64 supports encrypting Int64 data
type EncryptedInt64 struct {
	Field
	Raw int64
}

// Scan converts the value from the DB into a usable EncryptedInt64 value
func (s *EncryptedInt64) Scan(value interface{}) error {
	return decrypt(value.([]byte), &s.Raw)
}

// Value converts an initialized EncryptedInt64 value into a value that can safely be stored in the DB
func (s EncryptedInt64) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

// NullEncryptedInt64 supports encrypting nullable Int64 data
type NullEncryptedInt64 struct {
	Field
	Raw   int64
	Empty bool
}

// Scan converts the value from the DB into a usable NullEncryptedInt64 value
func (s *NullEncryptedInt64) Scan(value interface{}) error {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), &s.Raw)
}

// Value converts an initialized NullEncryptedInt64 value into a value that can safely be stored in the DB
func (s NullEncryptedInt64) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return encrypt(s.Raw)
}

// SignedInt64 supports signing Int64 data
type SignedInt64 struct {
	Field
	Raw   int64
	Valid bool
}

// Scan converts the value from the DB into a usable SignedInt64 value
func (s *SignedInt64) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized SignedInt64 value into a value that can safely be stored in the DB
func (s SignedInt64) Value() (driver.Value, error) {
	return sign(s.Raw)
}

// NullSignedInt64 supports signing nullable Int64 data
type NullSignedInt64 struct {
	Field
	Raw   int64
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedInt64 value
func (s *NullSignedInt64) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized NullSignedInt64 value into a value that can safely be stored in the DB
func (s NullSignedInt64) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return sign(s.Raw)
}

// SignedEncryptedInt64 supports signing and encrypting Int64 data
type SignedEncryptedInt64 struct {
	Field
	Raw   int64
	Valid bool
}

// Scan converts the value from the DB into a usable SignedEncryptedInt64 value
func (s *SignedEncryptedInt64) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized SignedEncryptedInt64 value into a value that can safely be stored in the DB
func (s SignedEncryptedInt64) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

// NullSignedEncryptedInt64 supports signing and encrypting nullable Int64 data
type NullSignedEncryptedInt64 struct {
	Field
	Raw   int64
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedEncryptedInt64 value
func (s *NullSignedEncryptedInt64) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = 0
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized NullSignedEncryptedInt64 value into a value that can safely be stored in the DB
func (s NullSignedEncryptedInt64) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return encryptSign(s.Raw)
}
