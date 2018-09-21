// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package r1

import (
	"crypto/sha256"

	"github.com/Nik-U/pbc"
)

// Symmetric pairing on the curve y^2 = x^3 + x over the finite field F_q with q of
// size 512 bits. The generated groups are of order 160 bits.
var pairing = pbc.GenerateA(160, 512).NewPairing()

type pk struct {
	Q0 *pbc.Element
	A  []byte // associated data
	l  int    // update count
	P  []*pbc.Element
}

type sk struct {
	P0 *pbc.Element
	Q  []*pbc.Element
	A  []byte // associated data
	l  int    // update count
	S  *pbc.Element
}

func gen() (*pk, *sk) {
	P0, P1 := pairing.NewG1().Rand(), pairing.NewG1().Rand()

	s0 := pairing.NewZr().Rand()

	S1 := pairing.NewG1().MulZn(P1, s0)
	Q0 := pairing.NewG1().MulZn(P0, s0)

	pk := &pk{Q0: Q0, A: []byte{}, l: 1, P: []*pbc.Element{P0, P1}}
	sk := &sk{P0: P0, Q: []*pbc.Element{nil}, A: []byte{}, l: 1, S: S1}

	return pk, sk
}

func (p *pk) update(ad []byte) {
	p.A = append(p.A, ad...)
	p.P = append(p.P, pairing.NewG1().SetFromStringHash(string(p.A), sha256.New()))
	p.l += 1

	return
}

func (s *sk) update(ad []byte) {
	s.A = append(s.A, ad...)
	Pl1 := pairing.NewG1().SetFromStringHash(string(s.A), sha256.New())

	sl := pairing.NewZr().Rand()

	s.Q = append(s.Q, pairing.NewG1().MulZn(s.P0, sl))
	s.S = pairing.NewG1().Add(s.S, pairing.NewG1().MulZn(Pl1, sl))
	s.l += 1

	return
}

func (p *pk) enc() (K *pbc.Element, C []*pbc.Element) {
	r := pairing.NewZr().Rand()

	K = pairing.NewGT().MulZn(pairing.NewGT().Pair(p.Q0, p.P[1]), r)

	C = make([]*pbc.Element, p.l+1)
	C[0] = pairing.NewG1().MulZn(p.P[0], r)
	C[1] = nil

	for i := 2; i < 1+p.l; i++ {
		C[i] = pairing.NewG1().MulZn(p.P[i], r)
	}

	return
}

func (s *sk) dec(C []*pbc.Element) (K *pbc.Element) {
	K = pairing.NewGT().Pair(C[0], s.S)

	for i := 2; i < 1+s.l; i++ {
		K = pairing.NewGT().Sub(K, pairing.NewGT().Pair(s.Q[i-1], C[i]))
	}

	return
}
