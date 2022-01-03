package encryption

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"

	"golang.org/x/crypto/nacl/box"
)

func init() {
	RegisterAlgo("naclbox", func(m map[string]interface{}) Algorithm {
		privKeySlice, _ := hex.DecodeString(m["private_key"].(string))
		privKey := [32]byte{}
		copy(privKey[:], privKeySlice)

		pubKeySlice, _ := hex.DecodeString(m["public_key"].(string))
		pubKey := [32]byte{}
		copy(pubKey[:], pubKeySlice)

		return NewNaClBox(&privKey, &pubKey)
	})
}

// NaClBox supports NaClBox enrcryption of arbitrary data
type NaClBox struct {
	Algorithm
	privateKey [32]byte
	publicKey  [32]byte
	sharedKey  [32]byte
}

// Name identifies the Algorithm as a string for exporting configurations
func (NaClBox) Name() string {
	return "naclbox"
}

// Config converts an Algorthim's internal configuration into a map for export
func (e NaClBox) Config() map[string]interface{} {
	return map[string]interface{}{
		"private_key": hex.EncodeToString(e.privateKey[:]),
		"public_key":  hex.EncodeToString(e.publicKey[:]),
	}
}

// NewNaClBox creates a new NaClBox value
func NewNaClBox(privateKey, publicKey *[32]byte) *NaClBox {
	sharedEncryptKey := new([32]byte)
	box.Precompute(sharedEncryptKey, publicKey, privateKey)

	return &NaClBox{
		privateKey: *privateKey,
		publicKey:  *publicKey,
		sharedKey:  *sharedEncryptKey,
	}
}

// Encrypt ::: NaClBox
func (e *NaClBox) Encrypt(plain []byte) ([]byte, error) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}

	encrypted := box.SealAfterPrecomputation(nonce[:], plain, &nonce, &e.sharedKey)

	return encrypted, nil
}

// Decrypt ::: NaClBox
func (e *NaClBox) Decrypt(crypted []byte) ([]byte, error) {
	var nonce [24]byte
	copy(nonce[:], crypted[:24])

	decrypted, ok := box.OpenAfterPrecomputation(nil, crypted[24:], &nonce, &e.sharedKey)
	if !ok {
		return nil, errors.New("decryption error")
	}

	return decrypted, nil
}
