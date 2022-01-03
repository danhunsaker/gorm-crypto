// Package encoding defines the various encoding Algorithms supported by the gormcrypto package
package encoding

// Algorithm is a bad name for the core interface all gormcrypto encodings implement. The name was chosen for consistency more than anything.
// A type implementing encoding.Algorithm will convert a value between its raw binary and encoded text forms, in a manner consistent with its type.
// The types implemented here wrap the Go standard library's various encoding packages.
type Algorithm interface {
	// Name identifies the Algorithm as a string for exporting configurations
	Name() string
	// Config converts an Algorthim's internal configuration into a map for export
	Config() map[string]interface{}
	// Encode transforms a binary value into a text encoding that can safely be serialized/stored.
	Encode([]byte) ([]byte, error)
	// Decode transforms a text encoding into a raw binary value which can be used for decryption/signature verification.
	Decode([]byte) ([]byte, error)
}

// RegisterAlgo adds an Algorithm to the internal algos map so it can be used in YAML configs
func RegisterAlgo(name string, creator func(map[string]interface{}) Algorithm) {
	algos[name] = creator
}

// SupportedAlgos returns a list of registered Algorithms that can be used in YAML configs
func SupportedAlgos() []string {
	keys := make([]string, 0, len(algos))
	for k := range algos {
		keys = append(keys, k)
	}
	return keys
}

// FromYaml configures an Algorithm automatically based on a name and a configuration map
func FromYaml(name string, config map[string]interface{}) Algorithm {
	return algos[name](config)
}

var algos map[string]func(map[string]interface{}) Algorithm

func init() {
	algos = make(map[string]func(map[string]interface{}) Algorithm, 0)
}
