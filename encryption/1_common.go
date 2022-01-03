// Package encryption defines the various encryption Algorithms supported by the gormcrypto package
package encryption

// Algorithm defines an interface that encryption types must implement to be usable with gormcrypto.
// A type implementing encryption.Algorithm will convert a value to and from its serialized and encrypted representations.
// The types implemented here wrap the Go standard (and extended) library's various (non-deprecated) crypto packages.
type Algorithm interface {
	// Name identifies the Algorithm as a string for exporting configurations
	Name() string
	// Config converts an Algorthim's internal configuration into a map for export
	Config() map[string]interface{}
	// Encrypt transforms plaintext values into a securely encrypted binary representation.
	Encrypt([]byte) ([]byte, error)
	// Decrypt transforms a securely encrypted binary value into its plaintext version.
	Decrypt([]byte) ([]byte, error)
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
