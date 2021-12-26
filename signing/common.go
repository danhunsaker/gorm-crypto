package signing

// Algorithm defines an interface that signing types must implement to be usable with gorm-crypto.
// A type implementing signing.Algorithm will supplement a value's' serialized representation with a cryptographic signature, or verify the same.
// The types implemented here wrap the Go standard (and extended) library's various (non-deprecated) crypto packages.
type Algorithm interface {
	// Sign generates a signature for the provided data that can be used to verify whether that data has been altered.
	Sign([]byte) ([]byte, error)
	// Verify checks whether a given piece of data has been altered since it was signed.
	Verify([]byte, []byte) (bool, error)
}
