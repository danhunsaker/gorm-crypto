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
	Encoder          encoding.Algorithm
	Serializer       serializing.Algorithm
	EncryptAlgorithm encryption.Algorithm
	SignAlgorithm    signing.Algorithm
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

// GlobalConfig ets the global config value.
// NOTE: This function will be deprecated at some point if I can work out how to properly make gormcrypto into a GORM plugin.
func GlobalConfig() Config {
	return config
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
	return fmt.Sprintf("{%s %s %s %s}", reflect.TypeOf(s.Encoder).String(), reflect.TypeOf(s.Serializer).String(), reflect.TypeOf(s.EncryptAlgorithm).String(), reflect.TypeOf(s.SignAlgorithm).String())
}

// PRIVATE

var config Config
