package serializing

import "encoding/xml"

type XML struct {
	Algorithm
}

func (x XML) Serialize(value interface{}) ([]byte, error) {
	return xml.Marshal(value)
}

func (x XML) Unserialize(source []byte, dest interface{}) error {
	return xml.Unmarshal(source, dest)
}
