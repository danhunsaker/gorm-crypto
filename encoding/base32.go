package encoding

import "encoding/base32"

type Base32 struct {
	Algorithm
}

func (b Base32) Encode(raw []byte) ([]byte, error) {
	return []byte(base32.StdEncoding.EncodeToString(raw)), nil
}

func (b Base32) Decode(encoded []byte) ([]byte, error) {
	return base32.StdEncoding.DecodeString(string(encoded))
}
