package serializing

// Algorithm is a bad name for the core interface all gorm-crypto serializers implement. The name was chosen for consistency more than anything.
// A type implementing serializing.Algorithm will convert a value between its Go type and a serialized text form, in a manner consistent with its type.
// The types implemented here wrap the Go standard library's various encoding packages.
type Algorithm interface {
	// Serialize transforms an arbitrary Go typed value into a byte slice that can be easily encrypted/signed.
	Serialize(interface{}) ([]byte, error)
	// Unserialize transforms a byte slice representation of a value into the Go type it represents.
	Unserialize([]byte, interface{}) error
}
