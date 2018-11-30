// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package signature

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"math/big"
	"strconv"

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
	N *big.Int
	U [bellareNumPoints]*big.Int
}

// bellarePrivateKey bundles the secret key material.
type bellarePrivateKey struct {
	N *big.Int
	S [bellareNumPoints]*big.Int

	J int // J specifies the current period of this private key.
}

// bellareSignature bundles signature material.
type bellareSignature struct {
	Y, Z *big.Int
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

	var S [bellareNumPoints]*big.Int
	var U [bellareNumPoints]*big.Int
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
		S[i], U[i] = s, u
	}

	pk, err = json.Marshal(&bellarePublicKey{N: N, U: U})
	if err != nil {
		return
	}
	sk, err = json.Marshal(&bellarePrivateKey{N: N, S: S, J: 0})
	return
}

// Update evolves a private key into a new period.
func (b Bellare) Update(sk []byte) ([]byte, error) {
	var private bellarePrivateKey
	if err := json.Unmarshal(sk, &private); err != nil {
		return nil, err
	}

	if private.J > bellareMaxPeriod {
		return nil, errors.New("private key has surpassed max period")
	}

	var S [bellareNumPoints]*big.Int
	for i := 0; i < bellareNumPoints; i++ {
		S[i] = new(big.Int).Exp(private.S[i], big.NewInt(2), private.N)
	}
	return json.Marshal(&bellarePrivateKey{N: private.N, S: S, J: private.J + 1})
}

// Sign creates a Bellare signature of a given message.
func (b Bellare) Sign(sk, msg []byte) ([]byte, error) {
	var private bellarePrivateKey
	if err := json.Unmarshal(sk, &private); err != nil {
		return nil, err
	}

	var R *big.Int
	for {
		R, _ = rand.Int(rand.Reader, private.N)
		if R.Uint64() != 0 {
			break
		}
	}
	e := new(big.Int).Exp(big.NewInt(2), big.NewInt(bellareMaxPeriod+1-int64(private.J)), nil)
	Y := new(big.Int).Exp(R, e, private.N)

	digest := primitives.Digest(sha512.New(), []byte(strconv.Itoa(private.J)), Y.Bytes(), msg)
	c := new(big.Int).SetBytes(digest)

	P := big.NewInt(1)
	for i := 0; i < bellareNumPoints; i++ {
		e := new(big.Int).And(new(big.Int).Rsh(c, uint(i)), big.NewInt(1))
		P = new(big.Int).Mul(P, new(big.Int).Exp(private.S[i], e, nil))
	}
	P = new(big.Int).Mul(R, P)
	Z := new(big.Int).Mod(P, private.N)

	return json.Marshal(&bellareSignature{Y: Y, Z: Z, J: private.J})
}

// Verify checks the validity of a given signature.
func (b Bellare) Verify(pk, msg, sig []byte) error {
	var public bellarePublicKey
	if err := json.Unmarshal(pk, &public); err != nil {
		return err
	}
	var signature bellareSignature
	if err := json.Unmarshal(sig, &signature); err != nil {
		return err
	}

	digest := primitives.Digest(sha512.New(), []byte(strconv.Itoa(signature.J)), signature.Y.Bytes(), msg)
	c := new(big.Int).SetBytes(digest)

	e := new(big.Int).Exp(big.NewInt(2), big.NewInt(bellareMaxPeriod+1-int64(signature.J)), nil)
	L := new(big.Int).Exp(signature.Z, e, public.N)

	P := big.NewInt(1)
	for i := 0; i < bellareNumPoints; i++ {
		e := new(big.Int).And(new(big.Int).Rsh(c, uint(i)), big.NewInt(1))
		P = new(big.Int).Mul(P, new(big.Int).Exp(public.U[i], e, nil))
	}
	P = new(big.Int).Mul(signature.Y, P)
	R := new(big.Int).Mod(P, public.N)

	if L.Cmp(R) != 0 {
		return errors.New("unable to verify signature")
	}
	return nil
}
