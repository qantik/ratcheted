// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package hibe

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/Nik-U/pbc"
)

const maxDepth = 50

type Boneh struct{}

type bonehParams struct {
	G, G1, G2, G3 *pbc.Element
	H             [maxDepth]*pbc.Element
}

type bonehEntity struct {
	ID [][]byte

	// FIXME
	G, G3 *pbc.Element
	H     [maxDepth]*pbc.Element

	A0, A1 *pbc.Element
	B      []*pbc.Element
}

type bonehCiphertext struct {
	V, W *pbc.Element
}

// NewBoneh creates a fresh protocol instance over a symmetric pairing.
func NewBoneh() *Boneh {
	return &Boneh{}
}

var (
	g1, g2, ss *pbc.Element
)

func (b Boneh) Setup(seed []byte) (params, root []byte, err error) {
	hash := func(base []byte, n int) []byte {
		sha := sha256.New()
		digest := seed
		for i := 0; i < n; i++ {
			sha.Write(digest)
			digest = sha.Sum(nil)
		}
		return digest
	}

	G := pairing.NewG1().SetFromHash(hash(seed, 1))
	alpha := pairing.NewZr().SetFromHash(hash(seed, 2))

	G1 := pairing.NewG1().MulZn(G, alpha)
	g1 = G1
	G2 := pairing.NewG1().SetFromHash(hash(seed, 3))
	g2 = G2
	G3 := pairing.NewG1().SetFromHash(hash(seed, 4))

	r := pairing.NewZr().SetFromHash(hash(seed, 5))
	A0 := pairing.NewG1().MulZn(G2, alpha)
	A0 = pairing.NewG1().Add(A0, pairing.NewG1().MulZn(G3, r))
	A1 := pairing.NewG1().MulZn(G, r)

	var H [maxDepth]*pbc.Element
	var B [maxDepth]*pbc.Element
	for i := 0; i < maxDepth; i++ {
		H[i] = pairing.NewG1().SetFromHash(hash(seed, i+6))
		B[i] = pairing.NewG1().MulZn(H[i], r)
	}

	p := &bonehParams{G: G, G1: G1, G2: G2, G3: G3, H: H}
	params, err = p.MarshalJSON()
	if err != nil {
		return
	}

	e := bonehEntity{
		ID: [][]byte{},
		G:  G, G3: G3,
		H:  H,
		A0: A0, A1: A1,
		B: B[:],
	}
	root, err = e.MarshalJSON()
	return
}

func (b Boneh) Extract(ancestor, id []byte) ([]byte, error) {
	var e bonehEntity
	if err := e.UnmarshalJSON(ancestor); err != nil {
		return nil, err
	}

	childID := append(e.ID, id)
	k := len(childID)
	t := pairing.NewZr().Rand()

	h := pairing.NewG1().Set1()
	for i := 0; i < k; i++ {
		j := pairing.NewZr().SetFromStringHash(string(childID[i]), sha256.New())
		h = pairing.NewG1().Add(h, pairing.NewG1().MulZn(e.H[i], j))
	}
	h = pairing.NewG1().Add(h, e.G3)
	h = pairing.NewG1().MulZn(h, t)

	ik := pairing.NewZr().SetFromStringHash(string(id), sha256.New())
	A0 := pairing.NewG1().Add(e.A0, pairing.NewG1().MulZn(e.B[0], ik))
	A0 = pairing.NewG1().Add(A0, h)

	A1 := pairing.NewG1().Add(e.A1, pairing.NewG1().MulZn(e.G, t))

	var B []*pbc.Element
	for i := k; i < maxDepth; i++ {
		B = append(B, pairing.NewG1().Add(e.B[i-k+1], pairing.NewG1().MulZn(e.H[i], t)))
	}

	child := &bonehEntity{
		ID: childID,
		G:  e.G, G3: e.G3,
		H:  e.H,
		A0: A0, A1: A1,
		B: B,
	}
	return child.MarshalJSON()
}

func (b Boneh) Encrypt(params, message []byte, id [][]byte) (c1, c2 []byte, err error) {
	var p bonehParams
	if err := p.UnmarshalJSON(params); err != nil {
		return nil, nil, err
	}

	s := pairing.NewZr().Rand()
	ss = s
	h := pairing.NewGT().MulZn(pairing.NewGT().Pair(p.G1, p.G2), s).Bytes()
	c1 = xor(message, h)

	V := pairing.NewG1().MulZn(p.G, s)

	W := pairing.NewG1().Set1()
	for i := 0; i < len(id); i++ {
		j := pairing.NewZr().SetFromStringHash(string(id[i]), sha256.New())
		W = pairing.NewG1().Add(W, pairing.NewG1().MulZn(p.H[i], j))
	}
	W = pairing.NewG1().Add(W, p.G3)
	W = pairing.NewG1().MulZn(W, s)

	ct := bonehCiphertext{V: V, W: W}
	c2, err = ct.MarshalJSON()
	return
}

func (b Boneh) Decrypt(entity, c1, c2 []byte) ([]byte, error) {
	var e bonehEntity
	if err := e.UnmarshalJSON(entity); err != nil {
		return nil, err
	}

	var c bonehCiphertext
	if err := c.UnmarshalJSON(c2); err != nil {
		return nil, err
	}

	fmt.Println(pairing.NewGT().MulZn(pairing.NewGT().Pair(g1, g2), ss).Bytes())

	n := pairing.NewGT().Pair(e.A1, c.W)
	d := pairing.NewGT().Pair(c.V, e.A0)
	fmt.Println(pairing.NewGT().Sub(n, d).Bytes())
	return xor(c1, pairing.NewGT().Sub(d, n).Bytes()), nil
}

// bonehParamsPacket is a helper structure that enables marshalling.
type bonehParamsPacket struct {
	G, G1, G2, G3 []byte
	H             [][]byte
}

func (p bonehParams) MarshalJSON() ([]byte, error) {
	packet := bonehParamsPacket{
		G:  p.G.CompressedBytes(),
		G1: p.G1.CompressedBytes(),
		G2: p.G2.CompressedBytes(),
		G3: p.G3.CompressedBytes(),
	}
	for _, h := range p.H {
		packet.H = append(packet.H, h.CompressedBytes())
	}
	return json.Marshal(&packet)
}

func (p *bonehParams) UnmarshalJSON(data []byte) error {
	var packet bonehParamsPacket
	if err := json.Unmarshal(data, &packet); err != nil {
		return err
	}
	p.G = pairing.NewG1().SetCompressedBytes(packet.G)
	p.G1 = pairing.NewG1().SetCompressedBytes(packet.G1)
	p.G2 = pairing.NewG1().SetCompressedBytes(packet.G2)
	p.G3 = pairing.NewG1().SetCompressedBytes(packet.G3)
	for i, h := range packet.H {
		p.H[i] = pairing.NewG1().SetCompressedBytes(h)
	}
	return nil
}

type bonehEntityPacket struct {
	ID     [][]byte
	G, G3  []byte
	H      [][]byte
	A0, A1 []byte
	B      [][]byte
}

func (e bonehEntity) MarshalJSON() ([]byte, error) {
	packet := bonehEntityPacket{
		ID: e.ID,
		G:  e.G.CompressedBytes(),
		G3: e.G3.CompressedBytes(),
		A0: e.A0.CompressedBytes(), A1: e.A1.CompressedBytes(),
	}
	for _, b := range e.B {
		packet.B = append(packet.B, b.CompressedBytes())
	}
	for _, h := range e.H {
		packet.H = append(packet.H, h.CompressedBytes())
	}
	return json.Marshal(&packet)
}

func (e *bonehEntity) UnmarshalJSON(data []byte) error {
	var packet bonehEntityPacket
	if err := json.Unmarshal(data, &packet); err != nil {
		return err
	}
	e.ID = packet.ID
	e.G = pairing.NewG1().SetCompressedBytes(packet.G)
	e.G3 = pairing.NewG1().SetCompressedBytes(packet.G3)
	e.A0 = pairing.NewG1().SetCompressedBytes(packet.A0)
	e.A1 = pairing.NewG1().SetCompressedBytes(packet.A1)
	for _, b := range packet.B {
		e.B = append(e.B, pairing.NewG1().SetCompressedBytes(b))
	}
	for i, h := range packet.H {
		e.H[i] = pairing.NewG1().SetCompressedBytes(h)
	}
	return nil
}

// bonehCiphertextPacket is a helper structure that enables marshalling.
type bonehCiphertextPacket struct {
	V, W []byte
}

func (e bonehCiphertext) MarshalJSON() ([]byte, error) {
	packet := bonehCiphertextPacket{V: e.V.CompressedBytes(), W: e.W.CompressedBytes()}
	return json.Marshal(&packet)
}

func (e *bonehCiphertext) UnmarshalJSON(data []byte) error {
	var packet bonehCiphertextPacket
	if err := json.Unmarshal(data, &packet); err != nil {
		return err
	}
	e.V = pairing.NewG1().SetCompressedBytes(packet.V)
	e.W = pairing.NewG1().SetCompressedBytes(packet.W)
	return nil
}
