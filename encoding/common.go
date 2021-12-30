// Package encoding defines the various encoding Algorithms supported by the gormcrypto package
package encoding

// Algorithm is a bad name for the core interface all gormcrypto encodings implement. The name was chosen for consistency more than anything.
// A type implementing encoding.Algorithm will convert a value between its raw binary and encoded text forms, in a manner consistent with its type.
// The types implemented here wrap the Go standard library's various encoding packages.
type Algorithm interface {
	// Encode transforms a binary value into a text encoding that can safely be serialized/stored.
	Encode([]byte) ([]byte, error)
	// Decode transforms a text encoding into a raw binary value which can be used for decryption/signature verification.
	Decode([]byte) ([]byte, error)
}
