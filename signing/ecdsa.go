package signing

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
)

type ECDSA struct {
	Algorithm
	private *ecdsa.PrivateKey
	public  *ecdsa.PublicKey
}

func NewECDSA(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) *ECDSA {
	return &ECDSA{
		private: privateKey,
		public:  publicKey,
	}
}

func (s *ECDSA) Sign(plain []byte) ([]byte, error) {
	hash := sha256.Sum256(plain)
	return ecdsa.SignASN1(rand.Reader, s.private, hash[:])
}

func (s *ECDSA) Verify(plain []byte, signature []byte) (bool, error) {
	hash := sha256.Sum256(plain)
	return ecdsa.VerifyASN1(s.public, hash[:], signature), nil
}
