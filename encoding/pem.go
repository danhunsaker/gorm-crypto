package encoding

import (
	"bytes"
	"encoding/pem"
)

func init() {
	RegisterAlgo("pem", func(m map[string]interface{}) Algorithm {
		return PEM{}
	})
}

// PEM supports PEM encoding of aritrary data
type PEM struct {
	Algorithm
}

// Name identifies the Algorithm as a string for exporting configurations
func (PEM) Name() string {
	return "pem"
}

// Config converts an Algorthim's internal configuration into a map for export
func (PEM) Config() map[string]interface{} {
	return nil
}

// Encode ::: PEM
func (h PEM) Encode(raw []byte) ([]byte, error) {
	var encoded bytes.Buffer
	err := pem.Encode(&encoded, &pem.Block{Type: "GORM-CRYPTO VALUE", Bytes: raw})

	return encoded.Bytes(), err
}

// Decode ::: PEM
func (h PEM) Decode(encoded []byte) ([]byte, error) {
	decoded, _ := pem.Decode(encoded)
	return decoded.Bytes, nil
}
