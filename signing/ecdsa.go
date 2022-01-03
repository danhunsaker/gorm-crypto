package signing

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
)

func init() {
	RegisterAlgo("ecdsa", func(m map[string]interface{}) Algorithm {
		data, _ := hex.DecodeString(m["key"].(string))
		privKey, _ := x509.ParseECPrivateKey(data)
		algo := NewECDSA(privKey, &privKey.PublicKey)
		return algo
	})
}

// ECDSA supports ECDSA
type ECDSA struct {
	Algorithm
	private *ecdsa.PrivateKey
	public  *ecdsa.PublicKey
}

// Name identifies the Algorithm as a string for exporting configurations
func (ECDSA) Name() string {
	return "ecdsa"
}

// Config converts an Algorthim's internal configuration into a map for export
func (s ECDSA) Config() map[string]interface{} {
	key, _ := x509.MarshalECPrivateKey(s.private)

	return map[string]interface{}{
		"key": hex.EncodeToString(key),
	}
}

// NewECDSA creates a new ECDSA value
func NewECDSA(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) *ECDSA {
	return &ECDSA{
		private: privateKey,
		public:  publicKey,
	}
}

// Sign ::: ECDSA
func (s *ECDSA) Sign(plain []byte) ([]byte, error) {
	hash := sha256.Sum256(plain)
	return ecdsa.SignASN1(rand.Reader, s.private, hash[:])
}

// Verify ::: ECDSA
func (s *ECDSA) Verify(plain []byte, signature []byte) (bool, error) {
	hash := sha256.Sum256(plain)
	return ecdsa.VerifyASN1(s.public, hash[:], signature), nil
}
