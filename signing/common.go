package signing

type Algorithm interface {
	Sign([]byte) ([]byte, error)
	Verify([]byte, []byte) (bool, error)
}
