package r2

import (
	"crypto/rand"
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

func (u *UNIARK) Send(sts []byte) (upd, k, ct []byte, err error) {
	var s sender
	if err = json.Unmarshal(sts, &s); err != nil {
		return
	}

	k = make([]byte, 16)
	if _, err = rand.Read(k); err != nil {
		return
	}

	ss, rr, err := u.Init()
	if err != nil {
		return nil, nil, nil, err
	}
	upd = ss

	ct, err = u.sc.Signcrypt(s.SKS, s.PKR, append(k, rr...))
	if err != nil {
		return
	}

	return
}

func (u *UNIARK) Receive(str, ct []byte) (upd, k []byte, err error) {
	var r receiver
	if err = json.Unmarshal(str, &r); err != nil {
		return
	}

	dec, err := u.sc.Unsigncrypt(r.SKR, r.PKS, ct)
	if err != nil {
		return nil, nil, err
	}

	k, upd = dec[:16], dec[16:]

	return
}
