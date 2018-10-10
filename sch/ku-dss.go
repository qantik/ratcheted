// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package sch

import (
	"encoding/json"
	"errors"

	"github.com/qantik/ratcheted/primitives/signature"
)

// kuDSS implements the key-updatable digital signature scheme based on a key-evolving
// digital signature scheme.
type kuDSS struct {
	signature signature.ForwardSignature
}

// kuDSSPublicKey bundles the public key material.
type kuDSSPublicKey struct {
	VK    []byte   // VK is the fs-DSS public key.
	Delta [][]byte // Delta is an array of associated data.

	I int // I is the current period of a live kuDSS instance.
}

// kuDSSPrivateKey bundles the private key material.
type kuDSSPrivateKey struct {
	SK    []byte   // SK is the fs-DSS private key.
	Sigma [][]byte // Sigma is an array of signed associated data.

	I int // I is the current period of a live kuDSS instance.
}

// kuDSSSignature bundles the signature material.
type kuDSSSignature struct {
	Signature []byte   // Signature is the fs-DSS signature.
	Sigma     [][]byte // Sigma is an array of signed associated data.

	I int // I is the period during which the signature has been created.
}

// generate creates a fresh public/private key pair.
func (k kuDSS) generate() (pk, sk []byte, err error) {
	fpk, fsk, err := k.signature.Generate()
	if err != nil {
		return nil, nil, err
	}

	pk, err = json.Marshal(&kuDSSPublicKey{VK: fpk, Delta: [][]byte{}, I: 0})
	if err != nil {
		return
	}
	sk, err = json.Marshal(&kuDSSPrivateKey{SK: fsk, Sigma: [][]byte{}, I: 0})
	return
}

// updatePublicKey evolves the public key into the next protocol period.
func (k kuDSS) updatePublicKey(pk, delta []byte) ([]byte, error) {
	var public kuDSSPublicKey
	if err := json.Unmarshal(pk, &public); err != nil {
		return nil, err
	}

	public.Delta = append(public.Delta, delta)
	public.I += 1

	return json.Marshal(&public)
}

// updatePrivateKey evolves the private key into the next protocol period.
func (k kuDSS) updatePrivateKey(sk, delta []byte) ([]byte, error) {
	var private kuDSSPrivateKey
	if err := json.Unmarshal(sk, &private); err != nil {
		return nil, err
	}

	sigma, err := k.signature.Sign(private.SK, append([]byte{0}, delta...))
	if err != nil {
		return nil, err
	}
	private.Sigma = append(private.Sigma, sigma)

	upd, err := k.signature.Update(private.SK)
	if err != nil {
		return nil, err
	}
	private.SK = upd
	private.I += 1

	return json.Marshal(&private)
}

// sign creates a signature of a message with a given private key.
func (k kuDSS) sign(sk, msg []byte) ([]byte, error) {
	var private kuDSSPrivateKey
	if err := json.Unmarshal(sk, &private); err != nil {
		return nil, err
	}

	sig, err := k.signature.Sign(private.SK, append([]byte{1}, msg...))
	if err != nil {
		return nil, err
	}

	return json.Marshal(&kuDSSSignature{Signature: sig, Sigma: private.Sigma, I: private.I})
}

// verify checks the validity of a signature.
func (k kuDSS) verify(pk, msg, sig []byte) error {
	var public kuDSSPublicKey
	if err := json.Unmarshal(pk, &public); err != nil {
		return err
	}
	var signature kuDSSSignature
	if err := json.Unmarshal(sig, &signature); err != nil {
		return err
	}

	if public.I != signature.I {
		return errors.New("mismatch between signature and public key periods")
	}

	plaintext := append([]byte{1}, msg...)
	if err := k.signature.Verify(public.VK, plaintext, signature.Signature); err != nil {
		return err
	}
	for i := 0; i < public.I-1; i++ {
		delta := append([]byte{0}, public.Delta[i]...)
		sigma := signature.Sigma[i]
		if err := k.signature.Verify(public.VK, delta, sigma); err != nil {
			return err
		}
	}
	return nil
}
