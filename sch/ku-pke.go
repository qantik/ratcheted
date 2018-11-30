// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package sch

import (
	"crypto/rand"

	"github.com/qantik/ratcheted/primitives"
	"github.com/qantik/ratcheted/primitives/hibe"
)

// kuPKE implements the key-updatable public-key encryption scheme based on a HIBE.
type kuPKE struct {
	hibe hibe.HIBE
}

// kuPKEPublicKey bundles the public key material.
type kuPKEPublicKey struct {
	PK []byte   // PK is the HIBE public parameters.
	I  [][]byte // I is an array of associated data.
}

// kuPKECiphertext bundles the two HIBE ciphertext parts.
type kuPKECiphertext struct {
	C1, C2 []byte
}

// generate creates a fresh public/private key pair.
func (k kuPKE) generate() (pk, sk []byte, err error) {
	var seed [16]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, nil, err
	}
	params, root, err := k.hibe.Setup(seed[:])
	if err != nil {
		return nil, nil, err
	}

	// Extract a first entity since root PKG is not able to perform encryptions.
	// This differs from the specification in the paper where the root PKGs is returned.
	sk, err = k.hibe.Extract(root, []byte{})
	if err != nil {
		return
	}

	pk, err = primitives.Encode(&kuPKEPublicKey{PK: params, I: [][]byte{[]byte{}}})
	return
}

// updatePublicKey creates a new public key.
func (k kuPKE) updatePublicKey(pk, delta []byte) ([]byte, error) {
	var public kuPKEPublicKey
	if err := primitives.Decode(pk, &public); err != nil {
		return nil, err
	}

	public.I = append(public.I, delta)
	return primitives.Encode(&public)
}

// updatePrivateKey creates a new private key.
func (k kuPKE) updatePrivateKey(sk, delta []byte) ([]byte, error) {
	return k.hibe.Extract(sk, delta)
}

// encrypt enciphers a message with a given public key.
func (k kuPKE) encrypt(pk, msg []byte) ([]byte, error) {
	var public kuPKEPublicKey
	if err := primitives.Decode(pk, &public); err != nil {
		return nil, err
	}

	c1, c2, err := k.hibe.Encrypt(public.PK, msg, public.I)
	if err != nil {
		return nil, err
	}
	return primitives.Encode(&kuPKECiphertext{C1: c1, C2: c2})
}

// decrypt deciphers a ciphertext with a given secret key.
func (k kuPKE) decrypt(sk, ct []byte) ([]byte, error) {
	var ciphertext kuPKECiphertext
	if err := primitives.Decode(ct, &ciphertext); err != nil {
		return nil, err
	}

	return k.hibe.Decrypt(sk, ciphertext.C1, ciphertext.C2)
}
