package serializing

import "encoding/json"

// JSON supports JSON
type JSON struct {
	Algorithm
}

// Serialize ::: JSON
func (j JSON) Serialize(value interface{}) ([]byte, error) {
	return json.Marshal(value)
}

// Unserialize ::: JSON
func (j JSON) Unserialize(source []byte, dest interface{}) error {
	return json.Unmarshal(source, dest)
}
