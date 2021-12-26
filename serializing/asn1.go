package serializing

import "encoding/asn1"

type ASN1 struct {
	Algorithm
}

func (j ASN1) Serialize(value interface{}) ([]byte, error) {
	return asn1.Marshal(value)
}

func (j ASN1) Unserialize(source []byte, dest interface{}) error {
	_, err := asn1.Unmarshal(source, dest)

	return err
}
