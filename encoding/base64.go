package encoding

import "encoding/base64"

func init() {
	RegisterAlgo("base64", func(m map[string]interface{}) Algorithm {
		return Base64{}
	})
}

// Base64 supports Base64 encoding of arbitrary data
type Base64 struct {
	Algorithm
}

// Name identifies the Algorithm as a string for exporting configurations
func (Base64) Name() string {
	return "base64"
}

// Config converts an Algorthim's internal configuration into a map for export
func (Base64) Config() map[string]interface{} {
	return nil
}

// Encode ::: Base64
func (Base64) Encode(raw []byte) ([]byte, error) {
	return []byte(base64.RawStdEncoding.EncodeToString(raw)), nil
}

// Decode ::: Base64
func (Base64) Decode(encoded []byte) ([]byte, error) {
	return base64.RawStdEncoding.DecodeString(string(encoded))
}
