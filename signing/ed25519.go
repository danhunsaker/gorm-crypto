package signing

import (
	"crypto/ed25519"
)

type ED25519 struct {
	Algorithm
	private *ed25519.PrivateKey
	public  *ed25519.PublicKey
}

func NewED25519(privateKey *ed25519.PrivateKey, publicKey *ed25519.PublicKey) *ED25519 {
	return &ED25519{
		private: privateKey,
		public:  publicKey,
	}
}

func (s *ED25519) Sign(plain []byte) ([]byte, error) {
	return ed25519.Sign(*s.private, plain), nil
}

func (s *ED25519) Verify(plain []byte, signature []byte) (bool, error) {
	return ed25519.Verify(*s.public, plain, signature), nil
}
