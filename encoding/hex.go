package encoding

import "encoding/hex"

func init() {
	RegisterAlgo("hex", func(m map[string]interface{}) Algorithm {
		return Hex{}
	})
}

// Hex supports Hex encoding of arbitrary data
type Hex struct {
	Algorithm
}

// Name identifies the Algorithm as a string for exporting configurations
func (Hex) Name() string {
	return "hex"
}

// Config converts an Algorthim's internal configuration into a map for export
func (Hex) Config() map[string]interface{} {
	return nil
}

// Encode ::: Hex
func (Hex) Encode(raw []byte) ([]byte, error) {
	return []byte(hex.EncodeToString(raw)), nil
}

// Decode ::: Hex
func (Hex) Decode(encoded []byte) ([]byte, error) {
	return hex.DecodeString(string(encoded))
}
