// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package r1

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"strconv"
)

type SRKE struct {
	kuKEM kuKEM
	ots   ots
}

func NewSRKE(kuKEM kuKEM, ots ots) *SRKE {
	return &SRKE{kuKEM: kuKEM, ots: ots}
}

type srkeSender struct {
	//pk     [][]byte
	pk     map[int][]byte
	e0, e1 int
	s      int
	//l      [][]byte
	l   map[int][]byte
	vfk []byte
	k   []byte
	km  []byte
	t   [][]byte
}

type srkeReceiver struct {
	//sk     [][]byte
	sk     map[int][]byte
	e0, e1 int
	r      int
	//l      [][]byte
	l   map[int][]byte
	sgk []byte
	k   []byte
	km  []byte
	t   [][]byte
}

func (s *SRKE) init() (*srkeSender, *srkeReceiver) {
	pk, sk := s.kuKEM.GenerateKeys()
	vfk, sgk := s.ots.GenerateKeys()

	k := make([]byte, 16)
	rand.Read(k)
	km := make([]byte, 16)
	rand.Read(km)

	sender := &srkeSender{
		pk: map[int][]byte{0: pk},
		e0: 0, e1: 0, s: 0,
		//l:   [][]byte{nil},
		l:   map[int][]byte{0: []byte{}},
		vfk: vfk,
		k:   k, km: km,
		t: [][]byte{},
	}
	receiver := &srkeReceiver{
		sk: map[int][]byte{0: sk},
		//sk: [][]byte{sk},
		e0: 0, e1: 0, r: 0,
		//l:   [][]byte{},
		l:   map[int][]byte{},
		sgk: sgk,
		k:   k, km: km,
		t: [][]byte{},
	}

	return sender, receiver
}

func (s *SRKE) senderSend(sender *srkeSender, ad []byte) (ko []byte, C [][]byte) {
	ks := []byte{}
	C = [][]byte{[]byte(strconv.Itoa(sender.e1))}

	for e := sender.e0; e <= sender.e1; e++ {
		k, c := s.kuKEM.Encrypt(sender.pk[e])
		ks, C = append(ks, k...), append(C, c)
	}

	tau := digest(hmac.New(sha256.New, sender.km), ad, bytes.Join(C, nil))
	C = append(C, tau)
	sender.t = append(sender.t, ad, bytes.Join(C, nil))

	sum := digest(sha512.New(), sender.k, ks, bytes.Join(sender.t, nil))
	ko, sender.k, sender.km = sum[0:16], sum[16:32], sum[32:48]

	sk := s.kuKEM.GenerateSecret(sum[48:64])
	pk := s.kuKEM.GeneratePublicFromSecret(sk)

	for i := 0; i < sender.e1; i++ {
		sender.pk[i] = nil
	}
	sender.pk[sender.e1] = pk

	sender.e0 = sender.e1
	sender.s += 1
	sender.l[sender.s] = append(ad, bytes.Join(C, nil)...)

	l := len(sender.pk) * 8
	l += len(sender.l) * 8
	for i := range sender.t {
		l += len(sender.t[i]) * 8
	}

	fmt.Println("sender:", l)

	return
}

func (s *SRKE) receiverSend(receiver *srkeReceiver, ad []byte) (C [][]byte) {
	pks, sks := s.kuKEM.GenerateKeys()
	vfks, sgks := s.ots.GenerateKeys()

	receiver.e1 += 1
	receiver.sk[receiver.e1] = sks

	C = append(C, []byte(strconv.Itoa(receiver.r)), pks, vfks)

	sigma := s.ots.Sign(receiver.sgk, append(ad, bytes.Join(C, nil)...))

	C = append(C, sigma)
	receiver.l[receiver.e1] = append(ad, bytes.Join(C, nil)...)

	receiver.sgk = sgks

	return
}

func (s *SRKE) receiverReceive(receiver *srkeReceiver, ad []byte, C [][]byte) (ko []byte) {
	ts := append([][]byte{ad}, C...)

	tau := C[len(C)-1]
	C = C[:len(C)-1]

	mac := digest(hmac.New(sha256.New, receiver.km), ad, bytes.Join(C, nil))
	if bytes.Compare(tau, mac) != 0 {
		panic("failed to verify mac")
	}

	e, _ := strconv.Atoi(string(C[0]))
	C = C[1:]

	if e < receiver.e0 || e > receiver.e1 {
		panic("invalid epoch value")
	}
	for i := receiver.e0 + 1; i <= e; i++ {
		receiver.t = append(receiver.t, receiver.l[i])
	}
	for i := 0; i < e; i++ {
		receiver.l[i] = nil
	}

	ks := []byte{}
	for i := receiver.e0; i <= e; i++ {
		c := C[0]
		C = C[1:]

		k := s.kuKEM.Decrypt(receiver.sk[i], c)
		ks = append(ks, k...)
	}
	receiver.t = append(receiver.t, ts...)

	sum := digest(sha512.New(), receiver.k, ks, bytes.Join(receiver.t, nil))
	ko, receiver.k, receiver.km = sum[0:16], sum[16:32], sum[32:48]

	sk := s.kuKEM.GenerateSecret(sum[48:64])
	for i := 0; i <= e-1; i++ {
		receiver.sk[i] = nil
	}
	receiver.sk[e] = sk

	for i := e + 1; i <= receiver.e1; i++ {
		receiver.sk[i] = s.kuKEM.UpdateSecret(receiver.sk[i], bytes.Join(ts, nil))
	}
	receiver.e0 = e
	receiver.r += 1

	l := len(receiver.sk) * 8
	l += len(receiver.l) * 8
	for i := range receiver.t {
		l += len(receiver.t[i]) * 8
	}

	fmt.Println("receiver:", l)

	return
}

func (s *SRKE) senderReceive(sender *srkeSender, ad []byte, C [][]byte) {
	sender.t = append(sender.t, ad, bytes.Join(C, nil))

	sigma := C[len(C)-1]
	C = C[:len(C)-1]

	if !s.ots.Verify(sender.vfk, append(ad, bytes.Join(C, nil)...), sigma) {
		panic("unable to verify ots")
	}

	r, _ := strconv.Atoi(string(C[0]))
	pks := C[1]
	sender.vfk = C[2]

	if sender.l[r] == nil {
		panic("transcript is nil")
	}
	for i := 0; i < r; i++ {
		sender.l[i] = nil
	}
	sender.l[r] = []byte{}

	for i := r + 1; i <= sender.s; i++ {
		pks = s.kuKEM.UpdatePublic(pks, sender.l[i])
	}

	sender.e1 += 1
	sender.pk[sender.e1] = pks

	return
}

//func (s *srkeSender) send(ad []byte) (ko []byte, C [][]byte) {
//	ks := [][]byte{}
//	C = [][]byte{[]byte(strconv.Itoa(s.Eend))}
//
//	for e := s.Estart; e <= s.Eend; e++ {
//		k, c := s.PK[e].enc()
//		ks = append(ks, k.Bytes())
//
//		for _, cc := range c {
//			if cc != nil {
//				C = append(C, cc.Bytes())
//			}
//		}
//	}
//
//	tau := digest(hmac.New(sha256.New, s.km), ad, bytes.Join(C, nil))
//	C = append(C, tau)
//	s.t = append(s.t, ad, bytes.Join(C, nil))
//
//	ko, K, km, sk := oracle(s.K, bytes.Join(ks, nil), bytes.Join(s.t, nil))
//	s.PK[s.Eend], s.K, s.km = sk.gen(), K, km
//
//	// TODO: key cancellation
//	s.Estart = s.Eend
//	s.s += 1
//	s.L = append(s.L, ad, bytes.Join(C, nil))
//
//	return
//}
//
//func (s *srkeReceiver) receive(ad []byte, C [][]byte) (ko []byte) {
//	_ = append([][]byte{ad}, C...)
//
//	tau := C[len(C)-1]
//	C = C[:len(C)-1]
//
//	if !bytes.Equal(tau, digest(hmac.New(sha256.New, s.km), ad, bytes.Join(C, nil))) {
//		panic("unable to verify hmac")
//	}
//
//	e, _ := strconv.Atoi(string(C[0]))
//	C = C[1:]
//
//	if !(e >= s.Estart && e <= s.Eend) {
//		panic("invalid epoch value")
//	}
//
//	return nil
//}
