package r1

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"strconv"
)

type upd struct {
	kem *kem
	ots ots
}

type user struct {
	s *s
	r *r
}

type s struct {
	pk        map[int][]byte
	e0, e1, s int
	l         map[int][]byte
	vfk       []byte
	k         []byte
	t         []byte
}

type r struct {
	sk        map[int][]byte
	e0, e1, r int
	l         map[int][]byte
	sgk       []byte
	k         []byte
	t         []byte
}

func NewUpd(hibe hhibe, ots ots) *upd {
	return &upd{kem: &kem{hibe: hibe}, ots: ots}
}

func (u upd) Init() (*user, *user, error) {
	vfka, sgka := u.ots.GenerateKeys()
	vfkb, sgkb := u.ots.GenerateKeys()

	var seed [128]byte
	rand.Read(seed[:])

	pka, ska, err := u.kem.Generate(seed[:])
	if err != nil {
		return nil, nil, err
	}

	rand.Read(seed[:])
	pkb, skb, err := u.kem.Generate(seed[:])
	if err != nil {
		return nil, nil, err
	}

	var ka [128]byte
	var kb [128]byte
	rand.Read(ka[:])
	rand.Read(kb[:])

	sa := &s{
		pk: map[int][]byte{0: pkb},
		e0: 0, e1: 0, s: 0,
		l:   map[int][]byte{0: []byte{}},
		vfk: vfkb, k: kb[:],
		t: []byte{},
	}
	ra := &r{
		sk: map[int][]byte{0: ska},
		e0: 0, e1: 0, r: 0,
		l:   map[int][]byte{},
		sgk: sgka, k: ka[:],
		t: []byte{},
	}
	a := &user{r: ra, s: sa}

	sb := &s{
		pk: map[int][]byte{0: pka},
		e0: 0, e1: 0, s: 0,
		l:   map[int][]byte{0: []byte{}},
		vfk: vfka, k: ka[:],
		t: []byte{},
	}
	rb := &r{
		sk: map[int][]byte{0: skb},
		e0: 0, e1: 0, r: 0,
		l:   map[int][]byte{},
		sgk: sgkb, k: kb[:],
		t: []byte{},
	}
	b := &user{r: rb, s: sb}

	return a, b, nil
}

func (u upd) oracle(k, ks, ts []byte) (ko, kss, km, coins []byte) {
	sha := sha512.New()
	sha.Write(k)
	sha.Write(ks)
	sha.Write(ts)
	sum := sha.Sum(nil)

	ko, kss, km, coins = sum[:16], sum[16:32], sum[32:48], sum[48:64]
	return
}

func (u upd) Send(user *user, ad []byte) ([]byte, [][]byte, error) {
	vfks, sgks := u.ots.GenerateKeys()

	var seed [128]byte
	rand.Read(seed[:])

	pks, sks, err := u.kem.Generate(seed[:])
	if err != nil {
		return nil, nil, err
	}

	user.r.e1 += 1
	user.r.sk[user.r.e1] = sks

	c := [][]byte{[]byte(strconv.Itoa(user.r.r)), pks, vfks, []byte(strconv.Itoa(user.s.e1))}
	ks := []byte{}
	for e := user.s.e0; e <= user.s.e1; e++ {
		c1, c2, err := u.kem.Encrypt(user.s.pk[e])
		if err != nil {
			return nil, nil, err
		}
		ks, c = append(ks, c1...), append(c, c2)
	}

	sigma := u.ots.Sign(user.r.sgk, append(ad, bytes.Join(c, nil)...))
	c = append(c, sigma)
	user.r.l[user.r.e1] = append(ad, bytes.Join(c, nil)...)
	user.r.sgk = sgks

	user.s.t = append(user.s.t, append(ad, bytes.Join(c, nil)...)...)
	//fmt.Println("sender k:", hex.EncodeToString(user.s.k))
	//fmt.Println("sender ks:", hex.EncodeToString(ks))
	//fmt.Println("sender t:", hex.EncodeToString(user.s.t))

	ko, kss, _, coins := u.oracle(user.s.k, ks, user.s.t)
	pk, _, err := u.kem.Generate(coins)
	if err != nil {
		return nil, nil, err
	}

	for i := 0; i < user.s.e1; i++ {
		user.s.pk[i] = nil
	}
	user.s.pk[user.s.e1] = pk
	user.s.e0 = user.s.e1
	user.s.s += 1
	user.s.k = kss
	user.s.l[user.s.s] = append(ad, bytes.Join(c, nil)...)

	return ko, c, nil
}

func (u upd) Receive(user *user, ad []byte, c [][]byte) ([]byte, error) {
	ts := append(ad, bytes.Join(c, nil)...)
	user.s.t = append(user.s.t, ts...)
	sigma := c[len(c)-1]
	c = c[:len(c)-1]
	if !u.ots.Verify(user.s.vfk, append(ad, bytes.Join(c, nil)...), sigma) {
		panic("llllllll")
	}

	r, pks, vfk := c[0], c[1], c[2]
	c = c[3:]
	rr, err := strconv.Atoi(string(r))
	if err != nil || user.s.l[rr] == nil {
		panic("rrrrrrrrrrrr")
	}
	for i := 0; i < rr; i++ {
		user.s.l[i] = nil
	}
	user.s.l[rr] = []byte{}

	for s := rr + 1; s <= user.s.s; s++ {
		pks, err = u.kem.UpdatePublicKey(pks, user.s.l[s])
		if err != nil {
			panic(err)
		}
	}
	user.s.e1 += 1
	user.s.pk[user.s.e1] = pks
	user.s.vfk = vfk

	ks := []byte{}
	e, _ := strconv.Atoi(string(c[0]))
	c = c[1:]
	if e < user.r.e0 || e > user.r.e1 {
		panic(e)
	}
	for i := user.r.e0 + 1; i <= e; i++ {
		user.r.t = append(user.r.t, user.r.l[i]...)
	}
	for i := 0; i <= e; i++ {
		user.r.l[i] = nil
	}

	for i := user.r.e0; i <= e; i++ {
		cc := c[0]
		c = c[1:]
		k, err := u.kem.Decrypt(user.r.sk[i], cc)
		if err != nil {
			return nil, err
		}
		ks = append(ks, k...)
	}
	user.r.t = append(user.r.t, ts...)
	//fmt.Println("receiver k:", hex.EncodeToString(user.r.k))
	//fmt.Println("receiver ks:", hex.EncodeToString(ks))
	//fmt.Println("receiver t:", hex.EncodeToString(user.r.t))
	ko, kr, _, coins := u.oracle(user.r.k, ks, user.r.t)
	_, sk, err := u.kem.Generate(coins)
	if err != nil {
		return nil, err
	}
	for i := 0; i <= e-1; i++ {
		user.r.sk[i] = nil
	}
	user.r.sk[e] = sk
	fmt.Println(e+1, user.r.e1)
	for i := e + 1; i <= user.r.e1; i++ {
		s, err := u.kem.UpdateSecretKey(user.r.sk[i], [][]byte{[]byte{}, ts})
		if err != nil {
			return nil, err
		}
		user.r.sk[i] = s
	}
	user.r.e0 = e
	user.r.r += 1
	user.r.k = kr

	return ko, nil
}
