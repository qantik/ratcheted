package hibe

import (
	"crypto/sha256"
	"encoding/json"

	"github.com/Nik-U/pbc"
)

// pairing (symmetric) on the curve y^2 = x^3 + over the finite field F_q with q
// of size 512 bits. The generated groups are of order 160 bits.
var pairing = pbc.GenerateA(160, 512).NewPairing()

type g1 struct{ *pbc.Element }
type gt struct{ *pbc.Element }
type zr struct{ *pbc.Element }

func pair(a, b *g1) *gt {
	return &gt{pairing.NewGT().Pair(a.Element, b.Element)}
}

func g1Rand() *g1 {
	return &g1{pairing.NewG1().Rand()}
}

func g1One() *g1 {
	return &g1{pairing.NewG1().Set1()}
}

func g1SetHash(hash []byte) *g1 {
	return &g1{pairing.NewG1().SetFromStringHash(string(hash), sha256.New())}
}

func zrRand() *zr {
	return &zr{pairing.NewZr().Rand()}
}

func (g g1) add(x *g1) *g1 {
	return &g1{pairing.NewG1().Add(g.Element, x.Element)}
}

func (g g1) mulZn(x *zr) *g1 {
	return &g1{pairing.NewG1().MulZn(g.Element, x.Element)}
}

func (g g1) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct{ Element []byte }{g.Bytes()})
}

func (g *g1) UnmarshalJSON(data []byte) error {
	var aux map[string][]byte
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	g.Element = pairing.NewG1().SetBytes(aux["Element"])
	return nil
}

func (g gt) sub(x *gt) *gt {
	return &gt{pairing.NewGT().Sub(g.Element, x.Element)}
}

func (g gt) mulZn(x *zr) *gt {
	return &gt{pairing.NewGT().MulZn(g.Element, x.Element)}
}

func (g gt) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct{ Element []byte }{g.Bytes()})
}

func (g *gt) UnmarshalJSON(data []byte) error {
	var aux map[string][]byte
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	g.Element = pairing.NewGT().SetBytes(aux["Element"])
	return nil
}

func (z zr) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct{ Element []byte }{z.Bytes()})
}

func (z *zr) UnmarshalJSON(data []byte) error {
	var aux map[string][]byte
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	z.Element = pairing.NewZr().SetBytes(aux["Element"])
	return nil
}

func marshal(obj interface{}) ([]byte, error) {
	return json.Marshal(&obj)
}

func unmarshal(data []byte, obj interface{}) error {
	return json.Unmarshal(data, &obj)
}
