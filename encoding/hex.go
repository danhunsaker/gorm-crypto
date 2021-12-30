package encoding

import "encoding/hex"

// Hex supports Hex
type Hex struct {
	Algorithm
}

// Encode ::: Hex
func (h Hex) Encode(raw []byte) ([]byte, error) {
	return []byte(hex.EncodeToString(raw)), nil
}

// Decode ::: Hex
func (h Hex) Decode(encoded []byte) ([]byte, error) {
	return hex.DecodeString(string(encoded))
}
