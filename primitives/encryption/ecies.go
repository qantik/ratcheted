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
	"encoding/gob"
	"errors"
	"io"
	"math/big"

	"golang.org/x/crypto/hkdf"

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
	Kx, Ky *big.Int
}

// eciesPrivateKey wraps a group scalar.
type eciesPrivateKey struct {
	K *big.Int
}

// eciesCiphertext bundles the ciphertext material.
type eciesCiphertext struct {
	Rx, Ry *big.Int
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

	public := &eciesPublicKey{Kx: Kx, Ky: Ky}
	pk, err = primitives.Encode(public)
	if err != nil {
		return
	}
	private := &eciesPrivateKey{K: k}
	sk, err = primitives.Encode(private)
	if err != nil {
		return
	}
	return
}

// Encrypt enciphers a message with a given public key.
func (e ECIES) Encrypt(pk, msg, ad []byte) ([]byte, error) {
	var public eciesPublicKey
	if err := primitives.Decode(pk, &public); err != nil {
		return nil, err
	}

	r, err := e.randomFieldScalar(nil)
	if err != nil {
		return nil, err
	}

	Rx, Ry := e.curve.ScalarBaseMult(r.Bytes())
	Px, _ := e.curve.ScalarMult(public.Kx, public.Ky, r.Bytes())

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

	var buffer bytes.Buffer
	enc := gob.NewEncoder(&buffer)

	ct := eciesCiphertext{Rx: Rx, Ry: Ry, C: c, D: d}
	if err = enc.Encode(&ct); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// Decrypt deciphers a ciphertex with a given private key.
func (e ECIES) Decrypt(sk, ct, ad []byte) ([]byte, error) {
	var private eciesPrivateKey
	if err := primitives.Decode(sk, &private); err != nil {
		return nil, err
	}
	var ciphertext eciesCiphertext
	buffer := bytes.NewBuffer(ct)
	dec := gob.NewDecoder(buffer)

	if err := dec.Decode(&ciphertext); err != nil {
		return nil, err
	}

	Px, _ := e.curve.ScalarMult(ciphertext.Rx, ciphertext.Ry, private.K.Bytes())

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

// Encapsulate creates a fresh symmetric key and encapsulates it using ECIES.
func (e ECIES) Encapsulate(pk []byte) (k, c []byte, err error) {
	var public eciesPublicKey
	if err := primitives.Decode(pk, &public); err != nil {
		return nil, nil, err
	}

	r, err := e.randomFieldScalar(nil)
	if err != nil {
		return nil, nil, err
	}

	Cx, Cy := e.curve.ScalarBaseMult(r.Bytes())
	c = elliptic.Marshal(e.curve, Cx, Cy)
	Px, _ := e.curve.ScalarMult(public.Kx, public.Ky, r.Bytes())

	hkdf := hkdf.New(sha256.New, append(c, Px.Bytes()...), nil, nil)

	k = make([]byte, 16)
	_, err = io.ReadFull(hkdf, k)
	return
}

// Decapsulate decrypts a ECIES ciphertext to extract the encapsulated symmetric key.
func (e ECIES) Decapsulate(sk, c []byte) ([]byte, error) {
	var private eciesPrivateKey
	if err := primitives.Decode(sk, &private); err != nil {
		return nil, err
	}

	Cx, Cy := elliptic.Unmarshal(e.curve, c)
	Qx, _ := e.curve.ScalarMult(Cx, Cy, private.K.Bytes())

	hkdf := hkdf.New(sha256.New, append(c, Qx.Bytes()...), nil, nil)

	k := make([]byte, 16)
	if _, err := io.ReadFull(hkdf, k); err != nil {
		return nil, err
	}
	return k, nil
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
