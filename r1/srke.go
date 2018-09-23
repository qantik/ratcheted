// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package r1

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"strconv"

	"github.com/Nik-U/pbc"
)

type srkeSender struct {
	PK     []*gentryPublic
	Estart int
	Eend   int
	s      int
	L      [][]byte
	vfk    *rsa.PublicKey
	K      []byte
	km     []byte
	t      [][]byte
}

type srkeReceiver struct {
	SK     []*gentrySecret
	Estart int
	Eend   int
	r      int
	L      [][]byte
	sgk    *rsa.PrivateKey
	K      []byte
	km     []byte
	t      [][]byte
}

type srkeCiphertext struct {
	e   int
	C   [][]*pbc.Element
	tau []byte
}

func srkeInit() (*srkeSender, *srkeReceiver) {
	sgk, _ := rsa.GenerateKey(rand.Reader, 2048)
	vfk := &sgk.PublicKey

	pk, sk := gen()

	K := make([]byte, 16)
	rand.Read(K)

	km := make([]byte, 16)
	rand.Read(km)

	snd := &srkeSender{
		PK:     []*gentryPublic{pk},
		Estart: 0, Eend: 0, s: 0,
		L:   [][]byte{},
		vfk: vfk,
		K:   K,
		km:  km,
		t:   [][]byte{},
	}

	rcv := &srkeReceiver{
		SK:     []*gentrySecret{sk},
		Estart: 0, Eend: 0, r: 0,
		L:   [][]byte{},
		sgk: sgk,
		K:   K,
		km:  km,
		t:   [][]byte{},
	}

	return snd, rcv
}

func oracle(seeds ...[]byte) (ko, K, km []byte, sk *gentrySecret) {
	sum := digest(sha512.New(), seeds...)

	ko, K, km = sum[0:16], sum[16:32], sum[32:48]
	sk = genSecret(sum[48:64])

	return
}

func (s *srkeSender) send(ad []byte) (ko []byte, C [][]byte) {
	ks := [][]byte{}
	C = [][]byte{[]byte(strconv.Itoa(s.Eend))}

	for e := s.Estart; e <= s.Eend; e++ {
		k, c := s.PK[e].enc()
		ks = append(ks, k.Bytes())

		for _, cc := range c {
			if cc != nil {
				C = append(C, cc.Bytes())
			}
		}
	}

	tau := digest(hmac.New(sha256.New, s.km), ad, bytes.Join(C, nil))
	C = append(C, tau)
	s.t = append(s.t, ad, bytes.Join(C, nil))

	ko, K, km, sk := oracle(s.K, bytes.Join(ks, nil), bytes.Join(s.t, nil))
	s.PK[s.Eend], s.K, s.km = sk.gen(), K, km

	// TODO: key cancellation
	s.Estart = s.Eend
	s.s += 1
	s.L = append(s.L, ad, bytes.Join(C, nil))

	return
}

func (s *srkeReceiver) receive(ad []byte, C [][]byte) (ko []byte) {
	_ = append([][]byte{ad}, C...)

	tau := C[len(C)-1]
	C = C[:len(C)-1]

	if !bytes.Equal(tau, digest(hmac.New(sha256.New, s.km), ad, bytes.Join(C, nil))) {
		panic("unable to verify hmac")
	}

	e, _ := strconv.Atoi(string(C[0]))
	C = C[1:]

	if !(e >= s.Estart && e <= s.Eend) {
		panic("invalid epoch value")
	}

	return nil
}
