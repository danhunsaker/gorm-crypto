package serializing

import "encoding/json"

type JSON struct {
	Algorithm
}

func (j JSON) Serialize(value interface{}) ([]byte, error) {
	return json.Marshal(value)
}

func (j JSON) Unserialize(source []byte, dest interface{}) error {
	return json.Unmarshal(source, dest)
}
