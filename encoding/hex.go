package encoding

import "encoding/hex"

type Hex struct {
	Algorithm
}

func (h Hex) Encode(raw []byte) ([]byte, error) {
	return []byte(hex.EncodeToString(raw)), nil
}

func (h Hex) Decode(encoded []byte) ([]byte, error) {
	return hex.DecodeString(string(encoded))
}
