// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package hibe

import (
	"crypto/sha256"
	"encoding/json"

	"github.com/Nik-U/pbc"
)

const maxDepth = 100

type Boneh struct{}

type bonehParams struct {
	G, G1, G2, G3 *pbc.Element
	H             [maxDepth]*pbc.Element
}

type bonehEntity struct {
	ID [][]byte

	A0, A1 *pbc.Element
	B      []*pbc.Element
}

// NewBoneh creates a fresh protocol instance over a symmetric pairing.
func NewBoneh() *Boneh {
	return &Boneh{}
}

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
	G2 := pairing.NewG1().SetFromHash(hash(seed, 3))
	G3 := pairing.NewG1().SetFromHash(hash(seed, 4))

	r := pairing.NewZr().SetFromHash(hash(seed, 5))
	A0 := pairing.NewG1().MulZn(G2, alpha)
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
		A0: A0, A1: A1,
		B: B[:],
	}
	root, err = e.MarshalJSON()
	return
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
	A0, A1 []byte
	B      [][]byte
}

func (e bonehEntity) MarshalJSON() ([]byte, error) {
	packet := bonehEntityPacket{ID: e.ID, A0: e.A0.CompressedBytes(), A1: e.A1.CompressedBytes()}
	for _, b := range e.B {
		packet.B = append(packet.B, b.CompressedBytes())
	}
	return json.Marshal(&packet)
}

func (e *bonehEntity) UnmarshalJSON(data []byte) error {
	var packet bonehEntityPacket
	if err := json.Unmarshal(data, &packet); err != nil {
		return err
	}
	e.ID = packet.ID
	e.A0 = pairing.NewG1().SetCompressedBytes(packet.A0)
	e.A1 = pairing.NewG1().SetCompressedBytes(packet.A1)
	for _, b := range packet.B {
		e.B = append(e.B, pairing.NewG1().SetCompressedBytes(b))
	}
	return nil
}
