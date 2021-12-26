package serializing

import (
	"bytes"
	"encoding/gob"
)

type GOB struct {
	Algorithm
}

func (g GOB) Serialize(value interface{}) ([]byte, error) {
	var hold bytes.Buffer
	enc := gob.NewEncoder(&hold)
	err := enc.Encode(value)
	return hold.Bytes(), err
}

func (g GOB) Unserialize(source []byte, dest interface{}) error {
	hold := bytes.NewBuffer(source)
	dec := gob.NewDecoder(hold)
	return dec.Decode(dest)
}
