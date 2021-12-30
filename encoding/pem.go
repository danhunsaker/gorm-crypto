package encoding

import (
	"bytes"
	"encoding/pem"
)

// PEM supports PEM
type PEM struct {
	Algorithm
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
