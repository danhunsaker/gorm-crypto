package serializing

type Algorithm interface {
	Serialize(interface{}) ([]byte, error)
	Unserialize([]byte, interface{}) error
}
