package encoding

import "encoding/base32"

func init() {
	RegisterAlgo("base32", func(m map[string]interface{}) Algorithm {
		return Base32{}
	})
}

// Base32 supports Base32 encoding of arbitrary data
type Base32 struct {
	Algorithm
}

// Name identifies the Algorithm as a string for exporting configurations
func (Base32) Name() string {
	return "base32"
}

// Config converts an Algorthim's internal configuration into a map for export
func (Base32) Config() map[string]interface{} {
	return nil
}

// Encode ::: Base32
func (Base32) Encode(raw []byte) ([]byte, error) {
	return []byte(base32.StdEncoding.EncodeToString(raw)), nil
}

// Decode ::: Base32
func (Base32) Decode(encoded []byte) ([]byte, error) {
	return base32.StdEncoding.DecodeString(string(encoded))
}
