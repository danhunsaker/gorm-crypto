// Package signing defines the various signing Algorithms supported by the gormcrypto package
package signing

// Algorithm defines an interface that signing types must implement to be usable with gormcrypto.
// A type implementing signing.Algorithm will supplement a value's' serialized representation with a cryptographic signature, or verify the same.
// The types implemented here wrap the Go standard (and extended) library's various (non-deprecated) crypto packages.
type Algorithm interface {
	// Name identifies the Algorithm as a string for exporting configurations
	Name() string
	// Config converts an Algorthim's internal configuration into a map for export
	Config() map[string]interface{}
	// Sign generates a signature for the provided data that can be used to verify whether that data has been altered.
	Sign([]byte) ([]byte, error)
	// Verify checks whether a given piece of data has been altered since it was signed.
	Verify([]byte, []byte) (bool, error)
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
