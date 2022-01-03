package signing

import (
	"crypto/ed25519"
	"encoding/hex"
)

func init() {
	RegisterAlgo("ed25519", func(m map[string]interface{}) Algorithm {
		seed, _ := hex.DecodeString(m["key"].(string))
		return NewED25519FromSeed(string(seed))
	})
}

// ED25519 supports ED25519
type ED25519 struct {
	Algorithm
	private *ed25519.PrivateKey
	public  *ed25519.PublicKey
}

// Name identifies the Algorithm as a string for exporting configurations
func (ED25519) Name() string {
	return "ed25519"
}

// Config converts an Algorthim's internal configuration into a map for export
func (s ED25519) Config() map[string]interface{} {
	return map[string]interface{}{
		"key": hex.EncodeToString(s.private.Seed()),
	}
}

// NewED25519 creates a new ED25519 value
func NewED25519(privateKey *ed25519.PrivateKey, publicKey *ed25519.PublicKey) *ED25519 {
	return &ED25519{
		private: privateKey,
		public:  publicKey,
	}
}

// NewED25519FromSeed creates a new ED25519FromSeed value
func NewED25519FromSeed(seed string) *ED25519 {
	privateKey := ed25519.NewKeyFromSeed([]byte(seed))
	publicKey := privateKey.Public().(ed25519.PublicKey)

	return &ED25519{
		private: &privateKey,
		public:  &publicKey,
	}
}

// Sign ::: ED25519
func (s *ED25519) Sign(plain []byte) ([]byte, error) {
	return ed25519.Sign(*s.private, plain), nil
}

// Verify ::: ED25519
func (s *ED25519) Verify(plain []byte, signature []byte) (bool, error) {
	return ed25519.Verify(*s.public, plain, signature), nil
}
