// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package secmsg

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"math/big"

	"github.com/pkg/errors"
	"github.com/qantik/ratcheted/primitives"
)

// skuPKE implements the secretly key-updatable encryption scheme.
type skuPKE struct {
	curve elliptic.Curve
}

// generate creates a fresh sku-PKE key pair.
func (s skuPKE) generate() (pk, sk []byte, err error) {
	private, x, y, err := elliptic.GenerateKey(s.curve, rand.Reader)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to generate sku-pke key pair")
	}

	pk = elliptic.Marshal(s.curve, x, y)
	sk = private
	return
}

// updateGen creates fresh update information for the public/private key pair.
func (s skuPKE) updateGen() (upk, usk []byte, err error) {
	return s.generate()
}

// updatePK refreshes the sku-PKE public key using the given update information.
func (s skuPKE) updatePK(upk, pk []byte) ([]byte, error) {
	pkx, pky := elliptic.Unmarshal(s.curve, pk)
	if pkx == nil {
		return nil, errors.New("unable to unmarshal sku-PKE public key")
	}
	upkx, upky := elliptic.Unmarshal(s.curve, upk)
	if upkx == nil {
		return nil, errors.New("unable to unmarshal sku-PKE update information")
	}

	x, y := s.curve.Add(pkx, pky, upkx, upky)
	return elliptic.Marshal(s.curve, x, y), nil
}

// updateSK refreshes the sku-PKE private key using the given update information.
func (s skuPKE) updateSK(usk, sk []byte) ([]byte, error) {
	private := new(big.Int).SetBytes(sk)
	uprivate := new(big.Int).SetBytes(usk)

	upd := new(big.Int).Add(private, uprivate)
	return new(big.Int).Mod(upd, s.curve.Params().N).Bytes(), nil
}

// encrypt enciphers a message with a given sku-pke public key. The message must not
// exceed 512 bytes.
func (s skuPKE) encrypt(pk, msg []byte) (c1, c2 []byte, err error) {
	if len(msg) > 512 {
		return nil, nil, errors.New("message exceeds maximal size of 512 bytes")
	}
	pkx, pky := elliptic.Unmarshal(s.curve, pk)
	if pkx == nil {
		return nil, nil, errors.New("unable to unmarshal sku-PKE public key")
	}

	gr, r, err := s.generate()
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to create curve elements")
	}

	hx, hy := s.curve.ScalarMult(pkx, pky, r)
	h := primitives.Digest(sha512.New(), elliptic.Marshal(s.curve, hx, hy))

	c1 = gr
	c2 = make([]byte, len(msg))
	for i := 0; i < len(msg); i++ {
		c2[i] = msg[i] ^ h[i]
	}
	return
}

// decrypt deciphers a ciphertext pair with a given sku-pke private key.
func (s skuPKE) decrypt(sk, c1, c2 []byte) ([]byte, error) {
	c1x, c1y := elliptic.Unmarshal(s.curve, c1)
	if c1x == nil {
		return nil, errors.New("unable to unmarshal sku-pke ciphertext")
	}

	hx, hy := s.curve.ScalarMult(c1x, c1y, sk)
	h := primitives.Digest(sha512.New(), elliptic.Marshal(s.curve, hx, hy))

	msg := make([]byte, len(c2))
	for i := 0; i < len(c2); i++ {
		msg[i] = h[i] ^ c2[i]
	}
	return msg, nil
}
