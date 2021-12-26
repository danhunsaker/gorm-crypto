package encoding

import (
	"bytes"
	"encoding/pem"
)

type PEM struct {
	Algorithm
}

func (h PEM) Encode(raw []byte) ([]byte, error) {
	var encoded bytes.Buffer
	err := pem.Encode(&encoded, &pem.Block{Type: "GORM-CRYPTO VALUE", Bytes: raw})

	return encoded.Bytes(), err
}

func (h PEM) Decode(encoded []byte) ([]byte, error) {
	decoded, _ := pem.Decode(encoded)
	return decoded.Bytes, nil
}
