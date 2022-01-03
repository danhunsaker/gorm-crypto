package serializing

import (
	"bytes"
	"encoding/gob"
)

func init() {
	RegisterAlgo("gob", func(m map[string]interface{}) Algorithm {
		return GOB{}
	})
}

// GOB supports GOB serialization of arbitrary data structures
type GOB struct {
	Algorithm
}

// Name identifies the Algorithm as a string for exporting configurations
func (GOB) Name() string {
	return "gob"
}

// Config converts an Algorthim's internal configuration into a map for export
func (GOB) Config() map[string]interface{} {
	return nil
}

// Serialize ::: GOB
func (g GOB) Serialize(value interface{}) ([]byte, error) {
	var hold bytes.Buffer
	enc := gob.NewEncoder(&hold)
	err := enc.Encode(value)
	return hold.Bytes(), err
}

// Unserialize ::: GOB
func (g GOB) Unserialize(source []byte, dest interface{}) error {
	hold := bytes.NewBuffer(source)
	dec := gob.NewDecoder(hold)
	return dec.Decode(dest)
}
