// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package bark

import (
	"encoding/json"
)

type UNIARK struct {
	sc *signcryption
}

type sender struct {
	SKS, PKR []byte
}

type receiver struct {
	SKR, PKS []byte
}

// uniarkBlock bundles the updated receiver state with a plaintext message.
type uniarkBlock struct {
	R, Message []byte
}

func NewUNIARK(sc *signcryption) *UNIARK {
	return &UNIARK{sc: sc}
}

func (u *UNIARK) Init() (s, r []byte, err error) {
	sks, skr, err := u.sc.generateSignKeys()
	if err != nil {
		return nil, nil, err
	}

	pks, pkr, err := u.sc.generateCipherKeys()
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

var sep = []byte{0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1}

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

	block, err := json.Marshal(&uniarkBlock{R: rr, Message: pt})
	if err != nil {
		return nil, nil, err
	}

	ct, err = u.sc.signcrypt(s.SKS, s.PKR, ad, block)
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

	dec, err := u.sc.unsigncrypt(r.SKR, r.PKS, ad, ct)
	if err != nil {
		return
	}

	var block uniarkBlock
	if err := json.Unmarshal(dec, &block); err != nil {
		return nil, nil, err
	}
	upd, pt = block.R, block.Message

	//l := split(dec)
	//upd, pt = l[0], l[1]

	return
}
