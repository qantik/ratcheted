// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package pt18

import (
	"encoding/json"

	"github.com/qantik/ratcheted/primitives/hibe"
)

// kuKEM designates the key-updatable key encapsulation mechanism object specified by
// a hierarchical identity-based encryption scheme.
type kuKEM struct {
	hibe hibe.HIBE
}

// kuKEMPublicKey is composed of the HIBE public parameters and associated data
// that acts as the HIBE public key.
type kuKEMPublicKey struct {
	PK []byte
	A  [][]byte
}

// generate creates a new ku-KEM key pair from a given seed.
func (k kuKEM) generate(seed []byte) (pk, sk []byte, err error) {
	params, root, err := k.hibe.Setup(seed)
	if err != nil {
		return nil, nil, err
	}

	// As specified in the paper the first entity has an empty id.
	sk, err = k.hibe.Extract(root, []byte{})
	if err != nil {
		return
	}

	pk, err = json.Marshal(&kuKEMPublicKey{PK: params, A: [][]byte{[]byte{}}})
	return
}

// updatePublicKey updates the ku-KEM public key.
func (k kuKEM) updatePublicKey(pk, ad []byte) ([]byte, error) {
	var p kuKEMPublicKey
	if err := json.Unmarshal(pk, &p); err != nil {
		return nil, err
	}

	p.A = append(p.A, ad)
	return json.Marshal(&p)
}

// updateSecretKey updates the ku-KEM secret key.
func (k kuKEM) updateSecretKey(sk []byte, ad []byte) ([]byte, error) {
	return k.hibe.Extract(sk, ad)
}

// encrypt generates a new key and encapsulate it in a ciphertext.
func (k kuKEM) encrypt(pk []byte) ([]byte, []byte, error) {
	var p kuKEMPublicKey
	if err := json.Unmarshal(pk, &p); err != nil {
		return nil, nil, err
	}

	return k.hibe.Encrypt(p.PK, nil, p.A)
}

// decrypt decapsulates an established key from a ciphertext.
func (k kuKEM) decrypt(sk, ct []byte) ([]byte, error) {
	return k.hibe.Decrypt(sk, nil, ct)
}
