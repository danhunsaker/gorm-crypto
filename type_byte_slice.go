package gc

import "database/sql/driver"

// EncryptedByteSlice supports encrypting ByteSlice data
type EncryptedByteSlice struct {
	Field
	Raw []byte
}

// Scan converts the value from the DB into a usable EncryptedByteSlice value
func (s *EncryptedByteSlice) Scan(value interface{}) error {
	return decrypt(value.([]byte), &s.Raw)
}

// Value converts an initialized EncryptedByteSlice value into a value that can safely be stored in the DB
func (s EncryptedByteSlice) Value() (driver.Value, error) {
	return encrypt(s.Raw)
}

// NullEncryptedByteSlice supports encrypting nullable ByteSlice data
type NullEncryptedByteSlice struct {
	Field
	Raw   []byte
	Empty bool
}

// Scan converts the value from the DB into a usable NullEncryptedByteSlice value
func (s *NullEncryptedByteSlice) Scan(value interface{}) error {
	if value == nil {
		s.Raw = []byte{}
		s.Empty = true
		return nil
	}

	return decrypt(value.([]byte), &s.Raw)
}

// Value converts an initialized NullEncryptedByteSlice value into a value that can safely be stored in the DB
func (s NullEncryptedByteSlice) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return encrypt(s.Raw)
}

// SignedByteSlice supports signing ByteSlice data
type SignedByteSlice struct {
	Field
	Raw   []byte
	Valid bool
}

// Scan converts the value from the DB into a usable SignedByteSlice value
func (s *SignedByteSlice) Scan(value interface{}) (err error) {
	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized SignedByteSlice value into a value that can safely be stored in the DB
func (s SignedByteSlice) Value() (driver.Value, error) {
	return sign(s.Raw)
}

// NullSignedByteSlice supports signing nullable ByteSlice data
type NullSignedByteSlice struct {
	Field
	Raw   []byte
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedByteSlice value
func (s *NullSignedByteSlice) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = []byte{}
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = verify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized NullSignedByteSlice value into a value that can safely be stored in the DB
func (s NullSignedByteSlice) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return sign(s.Raw)
}

// SignedEncryptedByteSlice supports signing and encrypting ByteSlice data
type SignedEncryptedByteSlice struct {
	Field
	Raw   []byte
	Valid bool
}

// Scan converts the value from the DB into a usable SignedEncryptedByteSlice value
func (s *SignedEncryptedByteSlice) Scan(value interface{}) (err error) {
	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized SignedEncryptedByteSlice value into a value that can safely be stored in the DB
func (s SignedEncryptedByteSlice) Value() (driver.Value, error) {
	return encryptSign(s.Raw)
}

// NullSignedEncryptedByteSlice supports signing and encrypting nullable ByteSlice data
type NullSignedEncryptedByteSlice struct {
	Field
	Raw   []byte
	Empty bool
	Valid bool
}

// Scan converts the value from the DB into a usable NullSignedEncryptedByteSlice value
func (s *NullSignedEncryptedByteSlice) Scan(value interface{}) (err error) {
	if value == nil {
		s.Raw = []byte{}
		s.Empty = true
		s.Valid = true
		return nil
	}

	s.Valid, err = decryptVerify(value.([]byte), &s.Raw)

	return
}

// Value converts an initialized NullSignedEncryptedByteSlice value into a value that can safely be stored in the DB
func (s NullSignedEncryptedByteSlice) Value() (driver.Value, error) {
	if s.Empty {
		return nil, nil
	}

	return encryptSign(s.Raw)
}
