package encoding

import "encoding/ascii85"

type ASCII85 struct {
	Algorithm
}

func (a ASCII85) Encode(raw []byte) (encoded []byte, err error) {
	ascii85.Encode(encoded, raw)
	return
}

func (a ASCII85) Decode(encoded []byte) (raw []byte, err error) {
	_, _, err = ascii85.Decode(raw, encoded, true)
	return
}
