package encoding

type Algorithm interface {
	Encode([]byte) ([]byte, error)
	Decode([]byte) ([]byte, error)
}
