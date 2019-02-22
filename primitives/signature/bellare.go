// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package signature

import (
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"math/big"
	"strconv"

	"github.com/alecthomas/binary"

	"github.com/qantik/ratcheted/primitives"
)

const (
	bellareSecurity  = 512  // security parameter in bits.
	bellareNumPoints = 10   // number of points in the keys.
	bellareMaxPeriod = 1000 // maximum value of allowed key evolutions.
)

// Bellare implements the forward-secure digital signature schemes proposed
// by Mihir Bellare and Sara Miner in their 1999 paper A Forward-Secure Digital
// Signature Scheme.
type Bellare struct{}

// bellarePublicKey bundles the public key material.
type bellarePublicKey struct {
	N []byte
	//U [bellareNumPoints][]byte
	U [][]byte
}

// bellarePrivateKey bundles the secret key material.
type bellarePrivateKey struct {
	N []byte
	//S [bellareNumPoints][]byte
	S [][]byte

	J int // J specifies the current period of this private key.
}

// bellareSignature bundles signature material.
type bellareSignature struct {
	Y, Z []byte
	J    int
}

// NewBellare creates a fresh Bellare protocol instance.
func NewBellare() *Bellare {
	return &Bellare{}
}

// Generate creates a Bellare public/private key pair.
func (b Bellare) Generate() (pk, sk []byte, err error) {
	var p *big.Int
	var q *big.Int
	for {
		p, _ = rand.Prime(rand.Reader, bellareSecurity/2)
		q, _ = rand.Prime(rand.Reader, bellareSecurity/2)

		rp := new(big.Int).Mod(p, big.NewInt(4))
		rq := new(big.Int).Mod(q, big.NewInt(4))
		if rp.Uint64() == 3 && rq.Uint64() == 3 {
			break
		}
	}

	N := new(big.Int).Mul(p, q)

	S := make([][]byte, bellareNumPoints)
	U := make([][]byte, bellareNumPoints)
	for i := 0; i < bellareNumPoints; i++ {
		var s *big.Int
		for {
			s, _ = rand.Int(rand.Reader, N)
			if s.Uint64() != 0 {
				break
			}
		}
		e := new(big.Int).Exp(big.NewInt(2), big.NewInt(bellareMaxPeriod+1), nil)
		u := new(big.Int).Exp(s, e, N)
		S[i], U[i] = s.Bytes(), u.Bytes()
	}

	pk, err = binary.Marshal(&bellarePublicKey{N: N.Bytes(), U: U})
	if err != nil {
		return
	}
	sk, err = binary.Marshal(&bellarePrivateKey{N: N.Bytes(), S: S, J: 0})
	return
}

// Update evolves a private key into a new period.
func (b Bellare) Update(sk []byte) ([]byte, error) {
	var private bellarePrivateKey
	if err := binary.Unmarshal(sk, &private); err != nil {
		return nil, err
	}

	if private.J > bellareMaxPeriod {
		return nil, errors.New("private key has surpassed max period")
	}

	n := new(big.Int).SetBytes(private.N)

	S := make([][]byte, bellareNumPoints)
	for i := 0; i < bellareNumPoints; i++ {
		s := new(big.Int).SetBytes(private.S[i])
		S[i] = new(big.Int).Exp(s, big.NewInt(2), n).Bytes()
	}
	return binary.Marshal(&bellarePrivateKey{N: private.N, S: S, J: private.J + 1})
}

// Sign creates a Bellare signature of a given message.
func (b Bellare) Sign(sk, msg []byte) ([]byte, error) {
	var private bellarePrivateKey
	if err := binary.Unmarshal(sk, &private); err != nil {
		return nil, err
	}

	n := new(big.Int).SetBytes(private.N)

	var R *big.Int
	for {
		R, _ = rand.Int(rand.Reader, n)
		if R.Uint64() != 0 {
			break
		}
	}
	e := new(big.Int).Exp(big.NewInt(2), big.NewInt(bellareMaxPeriod+1-int64(private.J)), nil)
	Y := new(big.Int).Exp(R, e, n)

	digest := primitives.Digest(sha512.New(), []byte(strconv.Itoa(private.J)), Y.Bytes(), msg)
	c := new(big.Int).SetBytes(digest)

	P := big.NewInt(1)
	for i := 0; i < bellareNumPoints; i++ {
		e := new(big.Int).And(new(big.Int).Rsh(c, uint(i)), big.NewInt(1))

		s := new(big.Int).SetBytes(private.S[i])
		P = new(big.Int).Mul(P, new(big.Int).Exp(s, e, nil))
	}
	P = new(big.Int).Mul(R, P)
	Z := new(big.Int).Mod(P, n)

	return binary.Marshal(&bellareSignature{Y: Y.Bytes(), Z: Z.Bytes(), J: private.J})
}

// Verify checks the validity of a given signature.
func (b Bellare) Verify(pk, msg, sig []byte) error {
	var public bellarePublicKey
	if err := binary.Unmarshal(pk, &public); err != nil {
		return err
	}
	var signature bellareSignature
	if err := binary.Unmarshal(sig, &signature); err != nil {
		return err
	}

	y, z := new(big.Int).SetBytes(signature.Y), new(big.Int).SetBytes(signature.Z)
	n := new(big.Int).SetBytes(public.N)

	digest := primitives.Digest(sha512.New(), []byte(strconv.Itoa(signature.J)), y.Bytes(), msg)
	c := new(big.Int).SetBytes(digest)

	e := new(big.Int).Exp(big.NewInt(2), big.NewInt(bellareMaxPeriod+1-int64(signature.J)), nil)
	L := new(big.Int).Exp(z, e, n)

	P := big.NewInt(1)
	for i := 0; i < bellareNumPoints; i++ {
		e := new(big.Int).And(new(big.Int).Rsh(c, uint(i)), big.NewInt(1))

		u := new(big.Int).SetBytes(public.U[i])
		P = new(big.Int).Mul(P, new(big.Int).Exp(u, e, nil))
	}
	P = new(big.Int).Mul(y, P)
	R := new(big.Int).Mod(P, n)

	if L.Cmp(R) != 0 {
		return errors.New("unable to verify signature")
	}
	return nil
}
