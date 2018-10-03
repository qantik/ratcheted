package r1

import (
	"encoding/json"
)

type hhibe interface {
	Setup(seed []byte) ([]byte, []byte, error)
	Extract(ancestor []byte, id []byte) ([]byte, error)
	Encrypt(params, message []byte, id [][]byte) ([]byte, []byte, error)
	Decrypt(entity, c1, c2 []byte) ([]byte, error)
}

// kuKEM designates the key-updatable key encapsulation mechanism object specified by
// a hierarchical identity-based encryption scheme.
type kem struct {
	hibe hhibe
}

// kuKEMPublicKey is composed of the HIBE public parameters and associated data
// that acts as the HIBE public key.
type kemPublicKey struct {
	PK []byte
	A  [][]byte
}

// generate creates a new ku-KEM key pair from a given seed.
func (k kem) generate(seed []byte) (pk, sk []byte, err error) {
	params, root, err := k.hibe.Setup(seed)
	if err != nil {
		return nil, nil, err
	}

	// As specified in the paper the first entity has an empty id.
	sk, err = k.hibe.Extract(root, []byte{})
	if err != nil {
		return
	}

	pk, err = json.Marshal(&kemPublicKey{PK: params, A: [][]byte{[]byte{}}})
	return
}

// updatePublicKey updates the ku-KEM public key.
func (k kem) updatePublicKey(pk, ad []byte) ([]byte, error) {
	var p kemPublicKey
	if err := json.Unmarshal(pk, &p); err != nil {
		return nil, err
	}

	p.A = append(p.A, ad)
	return json.Marshal(&p)
}

// updateSecretKey updates the ku-KEM secret key.
func (k kem) updateSecretKey(sk []byte, ad []byte) ([]byte, error) {
	return k.hibe.Extract(sk, ad)
}

// encrypt generates a new key and encapsulate it in a ciphertext.
func (k kem) encrypt(pk []byte) ([]byte, []byte, error) {
	var p kemPublicKey
	if err := json.Unmarshal(pk, &p); err != nil {
		return nil, nil, err
	}

	return k.hibe.Encrypt(p.PK, nil, p.A)
}

// decrypt decapsulates an established key from a ciphertext.
func (k kem) decrypt(sk, ct []byte) ([]byte, error) {
	return k.hibe.Decrypt(sk, nil, ct)
}
