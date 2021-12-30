package encoding

import "encoding/base32"

// Base32 supports Base32
type Base32 struct {
	Algorithm
}

// Encode ::: Base32
func (b Base32) Encode(raw []byte) ([]byte, error) {
	return []byte(base32.StdEncoding.EncodeToString(raw)), nil
}

// Decode ::: Base32
func (b Base32) Decode(encoded []byte) ([]byte, error) {
	return base32.StdEncoding.DecodeString(string(encoded))
}
