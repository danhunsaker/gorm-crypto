package signing

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
)

// ECDSA supports ECDSA
type ECDSA struct {
	Algorithm
	private *ecdsa.PrivateKey
	public  *ecdsa.PublicKey
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
