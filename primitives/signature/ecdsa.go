// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package signature

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"math/big"

	"github.com/qantik/ratcheted/primitives"
)

// ECDSA designates the ECDSA scheme handler object.
type ECDSA struct {
	curve elliptic.Curve
}

// NewECDSA creates a fresh ECDSA instance for a given elliptic curve.
func NewECDSA(curve elliptic.Curve) *ECDSA {
	return &ECDSA{curve: curve}
}

// Generate a fresh ECDSA public/private key pair.
func (e ECDSA) Generate() (pk, sk []byte, err error) {
	secret, err := ecdsa.GenerateKey(e.curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	sk, err = x509.MarshalECPrivateKey(secret)
	if err != nil {
		return nil, nil, err
	}
	pk, err = x509.MarshalPKIXPublicKey(&secret.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return
}

// Sign a message with a ECDSA private key.
func (e ECDSA) Sign(sk, msg []byte) ([]byte, error) {
	secret, err := x509.ParseECPrivateKey(sk)
	if err != nil {
		return nil, err
	}

	r, s, err := ecdsa.Sign(rand.Reader, secret, primitives.Digest(sha256.New(), msg))
	if err != nil {
		return nil, err
	}

	sig := append(r.Bytes(), s.Bytes()...)

	// FIXME: Every once in a while a signature with bogus length is created that cannot
	// be verified. In that case retry a new one.
	if len(sig) != e.signatureSize() {
		return e.Sign(sk, msg)
	}
	return sig, nil
}

// Verify checks the validity of a ECDSA signature.
func (e ECDSA) Verify(pk, msg, sig []byte) error {
	public, err := x509.ParsePKIXPublicKey(pk)
	if err != nil {
		return err
	}

	r := new(big.Int).SetBytes(sig[:e.signatureSize()/2])
	s := new(big.Int).SetBytes(sig[e.signatureSize()/2:])
	if !ecdsa.Verify(public.(*ecdsa.PublicKey), primitives.Digest(sha256.New(), msg), r, s) {
		return errors.New("unable to verify signature")
	}
	return nil
}

// signature size returns the size of a ECDSA signature based on the used curve in bytes.
func (e ECDSA) signatureSize() int {
	return 2 * e.curve.Params().BitSize / 8
}
