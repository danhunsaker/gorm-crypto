// Package encryption defines the various encryption Algorithms supported by the gormcrypto package
package encryption

// Algorithm defines an interface that encryption types must implement to be usable with gormcrypto.
// A type implementing encryption.Algorithm will convert a value to and from its serialized and encrypted representations.
// The types implemented here wrap the Go standard (and extended) library's various (non-deprecated) crypto packages.
type Algorithm interface {
	// Encrypt transforms plaintext values into a securely encrypted binary representation.
	Encrypt([]byte) ([]byte, error)
	// Decrypt transforms a securely encrypted binary value into its plaintext version.
	Decrypt([]byte) ([]byte, error)
}
