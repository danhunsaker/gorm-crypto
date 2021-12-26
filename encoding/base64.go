package encoding

import "encoding/base64"

type Base64 struct {
	Algorithm
}

func (b Base64) Encode(raw []byte) ([]byte, error) {
	return []byte(base64.RawStdEncoding.EncodeToString(raw)), nil
}

func (b Base64) Decode(encoded []byte) ([]byte, error) {
	return base64.RawStdEncoding.DecodeString(string(encoded))
}
