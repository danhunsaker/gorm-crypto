// Package gormcrypto is another library for encrypting/signing data with GORM
package gormcrypto

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"time"

	"github.com/danhunsaker/gorm-crypto/encoding"
	"github.com/danhunsaker/gorm-crypto/encryption"
	"github.com/danhunsaker/gorm-crypto/serializing"
	"github.com/danhunsaker/gorm-crypto/signing"
	"gopkg.in/yaml.v3"
)

// Config provides the global configuration data for gormcrypto.
// At the moment, that's just a list of different Setups your application supports.
// We support multiple Setups because application requirements change over time,
// and you'll want to be able to use values encrypted/signed by older keys/algorithms.
// The Time value used in the map indicates when the Setup was - or should be - made active in your code.
type Config struct {
	Setups map[time.Time]Setup
}

// Setup describes the way your data should be handled by gormcrypto.
// That includes the encryption algorithm/keys, the signing algorithm/keys,
// the mechanism for serializing values, and the encoding to use to coerce binary data into values that can safely be serialized/stored.
type Setup struct {
	Encoder    encoding.Algorithm
	Serializer serializing.Algorithm
	Encrypter  encryption.Algorithm
	Signer     signing.Algorithm
}

// Init sets up gormcrypto for use by telling it which Config to use.
// NOTE: This function may be deprecated at some point if I can work out how to properly make gormcrypto into a GORM plugin.
func Init(c Config) error {
	if len(c.Setups) < 1 {
		return errors.New("database cryptography configuration incomplete")
	}
	config = c

	return nil
}

// GlobalConfig gets the global config value.
// NOTE: This function will be deprecated at some point if I can work out how to properly make gormcrypto into a GORM plugin.
func GlobalConfig() Config {
	return config
}

// ConfigFromBytes converts a YAML document into a valid Config object
func ConfigFromBytes(contents []byte) (c Config) {
	var parsed yamlContents
	if err := yaml.Unmarshal(contents, &parsed); err == nil {
		c.Setups = make(map[time.Time]Setup, len(parsed))
		for setupTime, setupValue := range parsed {
			c.Setups[setupTime] = Setup{
				Encoder:    encoding.FromYaml(setupValue.Encoding.Algorithm, setupValue.Encoding.Config),
				Serializer: serializing.FromYaml(setupValue.Serializing.Algorithm, setupValue.Serializing.Config),
				Encrypter:  encryption.FromYaml(setupValue.Encryption.Algorithm, setupValue.Encryption.Config),
				Signer:     signing.FromYaml(setupValue.Signing.Algorithm, setupValue.Signing.Config),
			}
		}
	}

	return
}

// ConfigToBytes converts a Config value into a YAML-encoded byte slice for export to a file or other storage
func (c Config) ConfigToBytes() ([]byte, error) {
	configStruct := make(yamlContents, len(c.Setups))

	for t, s := range c.Setups {
		configStruct[t] = yamlSetup{
			Encoding: yamlSetupAlgorithm{
				Algorithm: s.Encoder.Name(),
				Config:    s.Encoder.Config(),
			},
			Serializing: yamlSetupAlgorithm{
				Algorithm: s.Serializer.Name(),
				Config:    s.Serializer.Config(),
			},
			Encryption: yamlSetupAlgorithm{
				Algorithm: s.Encrypter.Name(),
				Config:    s.Encrypter.Config(),
			},
			Signing: yamlSetupAlgorithm{
				Algorithm: s.Signer.Name(),
				Config:    s.Signer.Config(),
			},
		}
	}

	return yaml.Marshal(configStruct)
}

// CurrentSetup returns the most recent Setup value based on the Time it was set up under
func (c Config) CurrentSetup() Setup {
	return c.UsedSetup(time.Now())
}

// UsedSetup returns the most recent Setup value based on the passed Time, falling back to CurrentSetup
func (c Config) UsedSetup(at time.Time) Setup {
	keys := make([]time.Time, 0, len(c.Setups))
	for t := range c.Setups {
		keys = append(keys, t)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].Before(keys[j])
	})

	filtered := make([]time.Time, 0)
	for _, t := range keys {
		if at.Equal(t) || at.After(t) {
			filtered = append(filtered, t)
		}
	}
	if len(filtered) > 0 {
		return c.Setups[filtered[len(filtered)-1]]
	}

	return c.Setups[keys[len(keys)-1]]
}

// String converts the Setup to a string that indicates its components in a useful fashion
func (s Setup) String() string {
	return fmt.Sprintf("{%s %s %s %s}", reflect.TypeOf(s.Encoder).String(), reflect.TypeOf(s.Serializer).String(), reflect.TypeOf(s.Encrypter).String(), reflect.TypeOf(s.Signer).String())
}

// PRIVATE

var config Config

type yamlSetupAlgorithm struct {
	Algorithm string                 `yaml:"algorithm"`
	Config    map[string]interface{} `yaml:"config,omitempty"`
}

type yamlSetup struct {
	Encoding    yamlSetupAlgorithm `yaml:"encoding"`
	Serializing yamlSetupAlgorithm `yaml:"serializing"`
	Encryption  yamlSetupAlgorithm `yaml:"encryption"`
	Signing     yamlSetupAlgorithm `yaml:"signing"`
}

type yamlContents map[time.Time]yamlSetup
