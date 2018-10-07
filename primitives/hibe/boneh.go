// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package hibe

import (
	"crypto/sha256"
	"encoding/json"

	"github.com/Nik-U/pbc"
)

// maxDepth is the limit to how deep a Boneh hierarchy can reach.
const maxDepth = 10

// Boneh designates a Boneh-Boyen-Goh protocol instance.
type Boneh struct{}

// bonehParams composes the public parameters of a protocol instance.
type bonehParams struct {
	G, G1, G2, G3 *pbc.Element           // G, G1, G2, G3 are generator elements.
	H             [maxDepth]*pbc.Element // H are blinding factors.
}

// bonehEntity designates a participant in the protocol. It can be both the root PKG,
// intermediate PKG or a simple user.
type bonehEntity struct {
	// ID is public key of the entity. An entity at level t has an ID of lenght t,
	// the root PKG has an empty ID.
	ID [][]byte

	// FIXME: Normally, these public parameters should not be part of an entity
	// but without it it seems not to be possible to perform an extraction.
	G, G3 *pbc.Element
	H     [maxDepth]*pbc.Element

	// An entity secret key is composed of A0, A1 and an array B.
	A0, A1 *pbc.Element
	B      []*pbc.Element
}

// gentryCiphertext bundles a ciphertext.
type bonehCiphertext struct {
	V, W *pbc.Element
}

// NewBoneh creates a fresh protocol instance over a symmetric pairing.
func NewBoneh() *Boneh {
	return &Boneh{}
}

// Setup establishes the public parameters and generates a root entity PKG.
func (b Boneh) Setup(seed []byte) (params, root []byte, err error) {
	// In order to reuse the same seed for sampling multiple elements the seed is
	// iteratively hashed.
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
	e := bonehEntity{ID: [][]byte{}, G: G, G3: G3, H: H, A0: A0, A1: A1, B: B[:]}
	root, err = e.MarshalJSON()
	return
}

// Extract generates a fresh child entity specified by id from an ancestor entity.
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

	child := &bonehEntity{ID: childID, G: e.G, G3: e.G3, H: e.H, A0: A0, A1: A1, B: B}
	return child.MarshalJSON()
}

// Encrypt encrypts a messages for a given id. Note, that the ciphertext is split into two
// parts to simplify the integration in other protocols.
func (b Boneh) Encrypt(params, message []byte, id [][]byte) (c1, c2 []byte, err error) {
	var p bonehParams
	if err := p.UnmarshalJSON(params); err != nil {
		return nil, nil, err
	}

	s := pairing.NewZr().Rand()
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

// Decrypt decrypts a given ciphertext using the secret key material of an entity.
func (b Boneh) Decrypt(entity, c1, c2 []byte) ([]byte, error) {
	var e bonehEntity
	if err := e.UnmarshalJSON(entity); err != nil {
		return nil, err
	}

	var c bonehCiphertext
	if err := c.UnmarshalJSON(c2); err != nil {
		return nil, err
	}

	n := pairing.NewGT().Pair(e.A1, c.W)
	d := pairing.NewGT().Pair(c.V, e.A0)
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

// bonehEntityPacket is a helper structure that enables marshalling.
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
