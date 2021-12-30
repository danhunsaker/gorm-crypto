package serializing

import (
	"bytes"
	"encoding/gob"
)

// GOB supports GOB
type GOB struct {
	Algorithm
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
