package serializing

import "encoding/json"

func init() {
	RegisterAlgo("json", func(m map[string]interface{}) Algorithm {
		return JSON{}
	})
}

// JSON supports JSON serialization of arbitrary data structures
type JSON struct {
	Algorithm
}

// Name identifies the Algorithm as a string for exporting configurations
func (JSON) Name() string {
	return "json"
}

// Config converts an Algorthim's internal configuration into a map for export
func (JSON) Config() map[string]interface{} {
	return nil
}

// Serialize ::: JSON
func (j JSON) Serialize(value interface{}) ([]byte, error) {
	return json.Marshal(value)
}

// Unserialize ::: JSON
func (j JSON) Unserialize(source []byte, dest interface{}) error {
	return json.Unmarshal(source, dest)
}
