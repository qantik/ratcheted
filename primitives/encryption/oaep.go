// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package encryption

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"io"
	mr "math/rand"

	"github.com/pkg/errors"
)

var oaepKeySize = 2500

// OAEP implements to RSA-OAEP encryption scheme based on SHA256.
type OAEP struct{}

// NewOAEP creates a fresh RSA-OAEP instance.
func NewOAEP() *OAEP {
	return &OAEP{}
}

// Generate creates a fresh RSA-OAEP public/private key pair.
func (o OAEP) Generate(seed []byte) (pk, sk []byte, err error) {
	var reader io.Reader
	if seed == nil {
		reader = rand.Reader
	} else {
		// TODO: Find a more secure way to have deterministic streams.
		reader = mr.New(mr.NewSource(int64(binary.BigEndian.Uint64(seed))))
	}

	private, err := rsa.GenerateKey(reader, oaepKeySize)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to generate rsa-oaep key pair")
	}
	public := &private.PublicKey

	pk = x509.MarshalPKCS1PublicKey(public)
	sk = x509.MarshalPKCS1PrivateKey(private)
	return
}

// Encrypt enciphers a message and associated data with the given public key.
func (o OAEP) Encrypt(pk, msg, ad []byte) ([]byte, error) {
	public, err := x509.ParsePKCS1PublicKey(pk)
	if err != nil {
		return nil, errors.Wrap(err, "unable to unmarshal rsa-oaep public key")
	}

	ct, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, public, msg, ad)
	if err != nil {
		return nil, errors.Wrap(err, "unable to encrypt message")
	}
	return ct, err
}

// Decrypt deciphers a ciphertext and associated data with the given private key.
func (o OAEP) Decrypt(sk, ct, ad []byte) ([]byte, error) {
	private, err := x509.ParsePKCS1PrivateKey(sk)
	if err != nil {
		return nil, errors.Wrap(err, "unable to unmarshal rsa-oaep private key")
	}

	msg, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, private, ct, ad)
	if err != nil {
		return nil, errors.Wrap(err, "unable to decrypt ciphertext")
	}
	return msg, nil
}
