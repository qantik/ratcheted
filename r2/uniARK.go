package r2

import (
	"bytes"
	"encoding/json"
)

type UNIARK struct {
	sc *Signcryption
}

type sender struct {
	SKS, PKR []byte
}

type receiver struct {
	SKR, PKS []byte
}

func NewUNIARK(sc *Signcryption) *UNIARK {
	return &UNIARK{sc: sc}
}

func (u *UNIARK) Init() (s, r []byte, err error) {
	sks, skr, err := u.sc.GenerateSignKeys()
	if err != nil {
		return nil, nil, err
	}

	pks, pkr, err := u.sc.GenerateCipherKeys()
	if err != nil {
		return nil, nil, err
	}

	sender := &sender{SKS: sks, PKR: pkr}
	s, err = json.Marshal(sender)
	if err != nil {
		return
	}

	receiver := &receiver{SKR: skr, PKS: pks}
	r, err = json.Marshal(receiver)
	if err != nil {
		return
	}

	return
}

var sep = []byte{0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1}

func (u *UNIARK) Send(state, ad, pt []byte) (upd, ct []byte, err error) {
	var s sender
	if err = json.Unmarshal(state, &s); err != nil {
		return
	}

	ss, rr, err := u.Init()
	if err != nil {
		return nil, nil, err
	}
	upd = ss

	text := append(pt, append(sep, rr...)...)

	ct, err = u.sc.Signcrypt(s.SKS, s.PKR, ad, text)
	if err != nil {
		return
	}

	return
}

func (u *UNIARK) Receive(str, ad, ct []byte) (upd, pt []byte, err error) {
	var r receiver
	if err = json.Unmarshal(str, &r); err != nil {
		return
	}

	dec, err := u.sc.Unsigncrypt(r.SKR, r.PKS, ad, ct)
	if err != nil {
		return
	}

	l := bytes.Split(dec, sep)
	pt, upd = l[0], l[1]

	return
}
