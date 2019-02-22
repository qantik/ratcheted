// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package encryption

import (
	"bytes"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"io"
	"math/big"

	"golang.org/x/crypto/hkdf"

	"github.com/alecthomas/binary"

	"github.com/qantik/ratcheted/primitives"
)

// ECIES implements the Elliptic Curve Integrated Encryption Scheme on a given curve using
// HS256 and AES-GCM as the authentication and encryption primitives and HDKF for key derivation.
type ECIES struct {
	curve elliptic.Curve
	aes   *AES
}

// eciesPublicKey wraps the x and y coordinate of a group point.
type eciesPublicKey struct {
	Kx, Ky []byte
}

// eciesPrivateKey wraps a group scalar.
type eciesPrivateKey struct {
	K []byte
}

// eciesCiphertext bundles the ciphertext material.
type eciesCiphertext struct {
	Rx, Ry []byte
	C, D   []byte
}

// NewECIES creates a fresh ECIES object instance.
func NewECIES(curve elliptic.Curve) *ECIES {
	return &ECIES{curve: curve, aes: NewAES()}
}

// Generate creates a ECIES public/private key pair.
func (e ECIES) Generate(seed []byte) (pk, sk []byte, err error) {
	k, err := e.randomFieldScalar(primitives.Digest(sha512.New(), seed))
	if err != nil {
		return nil, nil, err
	}

	Kx, Ky := e.curve.ScalarBaseMult(k.Bytes())

	public := &eciesPublicKey{Kx: Kx.Bytes(), Ky: Ky.Bytes()}
	pk, err = binary.Marshal(public)
	if err != nil {
		return
	}
	private := &eciesPrivateKey{K: k.Bytes()}
	sk, err = binary.Marshal(private)
	if err != nil {
		return
	}
	return
}

// Encrypt enciphers a message with a given public key.
func (e ECIES) Encrypt(pk, msg, ad []byte) ([]byte, error) {
	var public eciesPublicKey
	if err := binary.Unmarshal(pk, &public); err != nil {
		return nil, err
	}

	kx, ky := new(big.Int).SetBytes(public.Kx), new(big.Int).SetBytes(public.Ky)

	r, err := e.randomFieldScalar(nil)
	if err != nil {
		return nil, err
	}

	Rx, Ry := e.curve.ScalarBaseMult(r.Bytes())
	Px, _ := e.curve.ScalarMult(kx, ky, r.Bytes())

	hkdf := hkdf.New(sha256.New, Px.Bytes(), nil, nil)

	ke := make([]byte, 16)
	if _, err := io.ReadFull(hkdf, ke); err != nil {
		return nil, err
	}
	km := make([]byte, 16)
	if _, err := io.ReadFull(hkdf, km); err != nil {
		return nil, err
	}

	c, err := e.aes.Encrypt(ke, msg)
	if err != nil {
		return nil, err
	}

	d := primitives.Digest(hmac.New(sha256.New, km), c)
	ct := eciesCiphertext{Rx: Rx.Bytes(), Ry: Ry.Bytes(), C: c, D: d}

	return binary.Marshal(&ct)
}

// Decrypt deciphers a ciphertex with a given private key.
func (e ECIES) Decrypt(sk, ct, ad []byte) ([]byte, error) {
	var private eciesPrivateKey
	if err := binary.Unmarshal(sk, &private); err != nil {
		return nil, err
	}
	var ciphertext eciesCiphertext
	if err := binary.Unmarshal(ct, &ciphertext); err != nil {
		return nil, err
	}

	rx, ry := new(big.Int).SetBytes(ciphertext.Rx), new(big.Int).SetBytes(ciphertext.Ry)

	Px, _ := e.curve.ScalarMult(rx, ry, private.K)

	hkdf := hkdf.New(sha256.New, Px.Bytes(), nil, nil)

	ke := make([]byte, 16)
	n, err := io.ReadFull(hkdf, ke)
	if n != len(ke) || err != nil {
		return nil, err
	}
	km := make([]byte, 16)
	n, err = io.ReadFull(hkdf, km)
	if n != len(km) || err != nil {
		return nil, err
	}

	tau := primitives.Digest(hmac.New(sha256.New, km), ciphertext.C)
	if !bytes.Equal(tau, ciphertext.D) {
		return nil, errors.New("failed to verify mac")
	}

	msg, err := e.aes.Decrypt(ke, ciphertext.C)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

// randomFieldElement returns a random group scalar.
func (e ECIES) randomFieldScalar(seed []byte) (*big.Int, error) {
	params := e.curve.Params()
	b := make([]byte, params.BitSize/8+8)

	var reader io.Reader
	if seed == nil {
		reader = rand.Reader
	} else {
		reader = bytes.NewReader(seed)
	}

	if _, err := io.ReadFull(reader, b); err != nil {
		return nil, err
	}

	one := new(big.Int).SetInt64(1)

	k := new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return k, nil
}
