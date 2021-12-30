package encoding

import "encoding/base64"

// Base64 supports Base64
type Base64 struct {
	Algorithm
}

// Encode ::: Base64
func (b Base64) Encode(raw []byte) ([]byte, error) {
	return []byte(base64.RawStdEncoding.EncodeToString(raw)), nil
}

// Decode ::: Base64
func (b Base64) Decode(encoded []byte) ([]byte, error) {
	return base64.RawStdEncoding.DecodeString(string(encoded))
}
