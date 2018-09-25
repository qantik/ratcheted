package hibe

type gentry struct {
	P0, Q0 *g1
}

type gentrySecret struct {
	St *zr
	S  *g1

	Q []*g1
}

func NewGentry() *gentry {
	return &gentry{}
}

func (g *gentry) GenerateKeys() (sk, pk []byte, err error) {
	g.P0 = g1Rand()

	s0 := zrRand()
	g.Q0 = g.P0.mulZn(s0)

	secret := gentrySecret{St: s0, S: g1One(), Q: []*g1{}}

	sk, err = marshal(&secret)
	if err != nil {
		return nil, nil, err
	}

	pk = []byte{}

	return
}

func (g *gentry) Extract(sk, id []byte) ([]byte, error) {
	var s gentrySecret
	if err := unmarshal(sk, &s); err != nil {
		return nil, err
	}

	P := g1SetHash(id)

	S := s.S.add(P.mulZn(s.St))
	St := zrRand()
	Q := append(s.Q, g.P0.mulZn(s.St))

	child := &gentrySecret{St: St, S: S, Q: Q}

	return marshal(&child)
}

func (g *gentry) Encrypt(msg, id []byte) ([]byte, []byte, error) {
	P := make([]*g1, len(id))
	for i := 0; i < len(id); i++ {
		P[i] = g1SetHash(id[:i+1])
	}

	r := zrRand()

	base := pair(g.Q0, P[0])
	h := base.mulZn(r).Bytes()
	v := xor(msg, h)

	u := make([]*g1, len(id)+1)
	u[0] = g.P0.mulZn(r)
	u[1] = nil

	for i := 2; i < len(id)+1; i++ {
		u[i] = P[i-1].mulZn(r)
	}

	c, err := marshal(&u)
	if err != nil {
		return nil, nil, err
	}

	return c, v, nil
}

func (g *gentry) Decrypt(sk, c, v []byte) ([]byte, error) {
	var s gentrySecret
	if err := unmarshal(sk, &s); err != nil {
		return nil, err
	}

	var u []*g1
	if err := unmarshal(c, &u); err != nil {
		return nil, err
	}

	k := pair(u[0], s.S)
	for i := 2; i < len(u); i++ {
		k = k.sub(pair(s.Q[i-1], u[i]))
	}

	return xor(v, k.Bytes()), nil
}

func xor(a, b []byte) []byte {
	c := make([]byte, len(a))
	for i := range a {
		c[i] = a[i] ^ b[i]
	}
	return c
}
