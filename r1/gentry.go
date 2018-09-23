// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package r1

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"io"

	"github.com/Nik-U/pbc"
)

// Symmetric pairing on the curve y^2 = x^3 + x over the finite field F_q with q of
// size 512 bits. The generated groups are of order 160 bits.
var pairing = pbc.GenerateA(160, 512).NewPairing()

type GentryKEM struct {
	rand io.Reader
}

type gentryCiphertext struct {
	C []*pbc.Element
}

type gentryCiphertextAux struct {
	C [][]byte
}

func (g *gentryCiphertext) encode() []byte {
	var aux gentryCiphertextAux
	aux.C = make([][]byte, 0)
	for _, c := range g.C {
		if c == nil {
			aux.C = append(aux.C, nil)
		} else {
			aux.C = append(aux.C, c.Bytes())
		}
	}

	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(&aux); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func (g *gentryCiphertext) decode(data []byte) {
	var aux gentryCiphertextAux
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&aux); err != nil {
		panic(err)
	}

	g.C = make([]*pbc.Element, 0)
	for _, c := range aux.C {
		if c == nil {
			g.C = append(g.C, nil)
		} else {
			g.C = append(g.C, pairing.NewG1().SetBytes(c))
		}
	}

	return
}

type gentryPublic struct {
	Q0 *pbc.Element
	A  []byte // associated data
	l  int    // update count
	P  []*pbc.Element
}

type gentryPublicAux struct {
	Q0 []byte
	A  []byte
	L  int
	P  [][]byte
}

func (g *gentryPublic) encode() []byte {
	var aux gentryPublicAux
	aux.Q0 = g.Q0.Bytes()
	aux.A = g.A
	aux.L = g.l
	aux.P = make([][]byte, 0)
	for _, p := range g.P {
		aux.P = append(aux.P, p.Bytes())
	}

	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(&aux); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func (g *gentryPublic) decode(data []byte) {
	var aux gentryPublicAux
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&aux); err != nil {
		panic(err)
	}

	g.Q0 = pairing.NewG1().SetBytes(aux.Q0)
	g.A = aux.A
	g.l = aux.L
	g.P = make([]*pbc.Element, 0)
	for _, p := range aux.P {
		g.P = append(g.P, pairing.NewG1().SetBytes(p))
	}

	return
}

type gentrySecret struct {
	P0 *pbc.Element
	Q  []*pbc.Element
	A  []byte // associated data
	l  int    // update count
	S  *pbc.Element
}

type gentrySecretAux struct {
	P0 []byte
	Q  [][]byte
	A  []byte
	L  int
	S  []byte
}

func (g *gentrySecret) encode() []byte {
	var aux gentrySecretAux
	aux.P0 = g.P0.Bytes()
	aux.A = g.A
	aux.L = g.l
	aux.S = g.S.Bytes()
	aux.Q = make([][]byte, 0)
	for _, q := range g.Q {
		if q == nil {
			aux.Q = append(aux.Q, nil)
		} else {
			aux.Q = append(aux.Q, q.Bytes())
		}
	}

	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(&aux); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func (g *gentrySecret) decode(data []byte) {
	var aux gentrySecretAux
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&aux); err != nil {
		panic(err)
	}

	g.P0 = pairing.NewG1().SetBytes(aux.P0)
	g.A = aux.A
	g.l = aux.L
	g.S = pairing.NewG1().SetBytes(aux.S)
	g.Q = make([]*pbc.Element, 0)
	for _, q := range aux.Q {
		if q == nil {
			g.Q = append(g.Q, nil)
		} else {
			g.Q = append(g.Q, pairing.NewG1().SetBytes(q))
		}
	}

	return
}

func NewGentryKEM(rand io.Reader) *GentryKEM {
	return &GentryKEM{rand: rand}
}

func (g *GentryKEM) GenerateKeys() (pk, sk []byte) {
	P0, P1 := pairing.NewG1().Rand(), pairing.NewG1().Rand()

	s0 := pairing.NewZr().Rand()

	S1 := pairing.NewG1().MulZn(P1, s0)
	Q0 := pairing.NewG1().MulZn(P0, s0)

	public := &gentryPublic{Q0: Q0, A: []byte{}, l: 1, P: []*pbc.Element{P0, P1}}
	secret := &gentrySecret{P0: P0, Q: []*pbc.Element{nil}, A: []byte{}, l: 1, S: S1}

	return public.encode(), secret.encode()
}

func gen() (*gentryPublic, *gentrySecret) {
	P0, P1 := pairing.NewG1().Rand(), pairing.NewG1().Rand()

	s0 := pairing.NewZr().Rand()

	S1 := pairing.NewG1().MulZn(P1, s0)
	Q0 := pairing.NewG1().MulZn(P0, s0)

	gentryPublic := &gentryPublic{Q0: Q0, A: []byte{}, l: 1, P: []*pbc.Element{P0, P1}}
	gentrySecret := &gentrySecret{P0: P0, Q: []*pbc.Element{nil}, A: []byte{}, l: 1, S: S1}

	return gentryPublic, gentrySecret
}

func genSecret(seed []byte) *gentrySecret {
	P0 := pairing.NewG1().SetFromHash(seed[:len(seed)/2])
	S1 := pairing.NewG1().SetFromHash(seed[len(seed)/2:])

	return &gentrySecret{P0: P0, Q: []*pbc.Element{nil}, A: []byte{}, l: 1, S: S1}
}

func (g *GentryKEM) GenerateSecret(seed []byte) []byte {
	P0 := pairing.NewG1().SetFromHash(seed[:len(seed)/2])
	S1 := pairing.NewG1().SetFromHash(seed[len(seed)/2:])

	secret := &gentrySecret{P0: P0, Q: []*pbc.Element{nil}, A: []byte{}, l: 1, S: S1}
	return secret.encode()
}

func (s *gentrySecret) gen() *gentryPublic {
	s0 := pairing.NewZr().Rand()

	P1 := pairing.NewG1().MulZn(s.S, pairing.NewZr().Invert(s0))
	Q0 := pairing.NewG1().MulZn(s.P0, s0)

	return &gentryPublic{Q0: Q0, A: []byte{}, l: 1, P: []*pbc.Element{s.P0, P1}}
}

func (g *GentryKEM) GeneratePublicFromSecret(secret []byte) []byte {
	s := &gentrySecret{}
	s.decode(secret)

	s0 := pairing.NewZr().Rand()

	P1 := pairing.NewG1().MulZn(s.S, pairing.NewZr().Invert(s0))
	Q0 := pairing.NewG1().MulZn(s.P0, s0)

	public := &gentryPublic{Q0: Q0, A: []byte{}, l: 1, P: []*pbc.Element{s.P0, P1}}
	return public.encode()
}

func (p *gentryPublic) update(ad []byte) {
	p.A = append(p.A, ad...)
	p.P = append(p.P, pairing.NewG1().SetFromStringHash(string(p.A), sha256.New()))
	p.l += 1

	return
}

func (g *GentryKEM) UpdatePublic(public, ad []byte) []byte {
	p := &gentryPublic{}
	p.decode(public)

	p.A = append(p.A, ad...)
	p.P = append(p.P, pairing.NewG1().SetFromStringHash(string(p.A), sha256.New()))
	p.l += 1

	return p.encode()
}

func (s *gentrySecret) update(ad []byte) {
	s.A = append(s.A, ad...)
	Pl1 := pairing.NewG1().SetFromStringHash(string(s.A), sha256.New())

	sl := pairing.NewZr().Rand()

	s.Q = append(s.Q, pairing.NewG1().MulZn(s.P0, sl))
	s.S = pairing.NewG1().Add(s.S, pairing.NewG1().MulZn(Pl1, sl))
	s.l += 1

	return
}

func (g *GentryKEM) UpdateSecret(secret, ad []byte) []byte {
	s := &gentrySecret{}
	s.decode(secret)

	s.A = append(s.A, ad...)
	Pl1 := pairing.NewG1().SetFromStringHash(string(s.A), sha256.New())

	sl := pairing.NewZr().Rand()

	s.Q = append(s.Q, pairing.NewG1().MulZn(s.P0, sl))
	s.S = pairing.NewG1().Add(s.S, pairing.NewG1().MulZn(Pl1, sl))
	s.l += 1

	return s.encode()
}

func (p *gentryPublic) enc() (K *pbc.Element, C []*pbc.Element) {
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

func (g *GentryKEM) Encrypt(public []byte) ([]byte, []byte) {
	p := &gentryPublic{}
	p.decode(public)

	r := pairing.NewZr().Rand()

	K := pairing.NewGT().MulZn(pairing.NewGT().Pair(p.Q0, p.P[1]), r)

	C := make([]*pbc.Element, p.l+1)
	C[0] = pairing.NewG1().MulZn(p.P[0], r)
	C[1] = nil

	for i := 2; i < 1+p.l; i++ {
		C[i] = pairing.NewG1().MulZn(p.P[i], r)
	}

	aux := &gentryCiphertext{C: C}
	return K.Bytes(), aux.encode()
}

func (s *gentrySecret) dec(C []*pbc.Element) (K *pbc.Element) {
	K = pairing.NewGT().Pair(C[0], s.S)

	for i := 2; i < 1+s.l; i++ {
		K = pairing.NewGT().Sub(K, pairing.NewGT().Pair(s.Q[i-1], C[i]))
	}

	return
}

func (g *GentryKEM) Decrypt(secret, cipher []byte) []byte {
	s := &gentrySecret{}
	s.decode(secret)

	c := &gentryCiphertext{}
	c.decode(cipher)

	K := pairing.NewGT().Pair(c.C[0], s.S)

	for i := 2; i < 1+s.l; i++ {
		K = pairing.NewGT().Sub(K, pairing.NewGT().Pair(s.Q[i-1], c.C[i]))
	}

	return K.Bytes()
}
