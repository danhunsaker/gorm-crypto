package encryption

import (
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/nacl/box"
)

type NaClBox struct {
	Algorithm
	sharedKey [32]byte
}

func NewNaClBox(publicKey, privateKey *[32]byte) NaClBox {
	sharedEncryptKey := new([32]byte)
	box.Precompute(sharedEncryptKey, publicKey, privateKey)

	return NaClBox{
		sharedKey: *sharedEncryptKey,
	}
}

func (e *NaClBox) Encrypt(plain []byte) ([]byte, error) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}

	encrypted := box.SealAfterPrecomputation(nonce[:], plain, &nonce, &e.sharedKey)

	return encrypted, nil
}

func (e *NaClBox) Decrypt(crypted []byte) ([]byte, error) {
	var nonce [24]byte
	copy(nonce[:], crypted[:24])

	decrypted, ok := box.OpenAfterPrecomputation(nil, crypted[24:], &nonce, &e.sharedKey)
	if !ok {
		return nil, errors.New("decryption error")
	}

	return decrypted, nil
}
