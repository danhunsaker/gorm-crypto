package encoding

import (
	"bytes"
	"encoding/ascii85"
)

func init() {
	RegisterAlgo("ascii85", func(m map[string]interface{}) Algorithm {
		return ASCII85{}
	})
}

// ASCII85 supports ASCII85 encoding of arbitrary data
type ASCII85 struct {
	Algorithm
}

const blockSize = 4

// Name identifies the Algorithm as a string for exporting configurations
func (ASCII85) Name() string {
	return "ascii85"
}

// Config converts an Algorthim's internal configuration into a map for export
func (ASCII85) Config() map[string]interface{} {
	return nil
}

// Encode ::: ASCII85
func (ASCII85) Encode(raw []byte) ([]byte, error) {
	padded := 0

	if f := len(raw) % blockSize; f != 0 {
		padded = blockSize - f
		raw = append(raw, bytes.Repeat([]byte{byte(padded)}, padded)...)
	}
	encoded := make([]byte, ascii85.MaxEncodedLen(len(raw))+1)
	encoded[0] = byte(padded)
	ascii85.Encode(encoded[1:], raw)

	return encoded, nil
}

// Decode ::: ASCII85
func (ASCII85) Decode(encoded []byte) ([]byte, error) {
	decoded := make([]byte, len(encoded)-1)
	trimTo, _, err := ascii85.Decode(decoded, encoded[1:], true)
	if err != nil {
		return nil, err
	}

	raw := make([]byte, trimTo)
	copy(raw, decoded)

	if len(raw) > 0 {
		padded := encoded[0]
		suffix := bytes.Repeat([]byte{padded}, int(padded))
		return bytes.TrimSuffix(raw, suffix), nil
	}

	return raw, nil
}
