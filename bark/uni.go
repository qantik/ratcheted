// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package bark

import (
	"github.com/pkg/errors"

	"github.com/qantik/ratcheted/primitives"
)

type Uni struct {
	sc *signcryption
}

type sender struct {
	SKS, PKR []byte
}

type receiver struct {
	SKR, PKS []byte
}

// uniBlock bundles the updated receiver state with a plaintext message.
type uniBlock struct {
	R, Message []byte
}

func NewUni(sc *signcryption) *Uni {
	return &Uni{sc: sc}
}

func (u Uni) Init() (s, r []byte, err error) {
	sks, skr, err := u.sc.generateSignKeys()
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to generate signcryption signature keys")
	}

	pks, pkr, err := u.sc.generateCipherKeys()
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to generate signcryption cipher keys")
	}

	s, err = primitives.Encode(sender{SKS: sks, PKR: pkr})
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to encode uni-bark sender")
	}
	r, err = primitives.Encode(receiver{SKR: skr, PKS: pks})
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to encode uni-bark receiver")
	}
	return
}

func (u Uni) Send(state, ad, pt []byte, simple bool) (upd, ct []byte, err error) {
	var s sender
	if err := primitives.Decode(state, &s); err != nil {
		return nil, nil, errors.Wrap(err, "unable to decode uni-bark sender state")
	}

	// Only create new uni-bark state for the inner-most onion layer.
	var us, ur []byte
	if !simple {
		us, ur, err = u.Init()
		if err != nil {
			return nil, nil, errors.Wrap(err, "unable to create new uni-bark instance")
		}
	}
	upd = us

	block, err := primitives.Encode(uniBlock{R: ur, Message: pt})
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to encode uni-bark message")
	}

	ct, err = u.sc.signcrypt(s.SKS, s.PKR, ad, block)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to signcrypt uni-bark message")
	}
	return
}

func (u Uni) Receive(str, ad, ct []byte) (upd, pt []byte, err error) {
	var r receiver
	if err := primitives.Decode(str, &r); err != nil {
		return nil, nil, errors.Wrap(err, "unable to decode uni-bark receiver state")
	}

	dec, err := u.sc.unsigncrypt(r.SKR, r.PKS, ad, ct)
	if err != nil {
		return
	}

	var block uniBlock
	if err := primitives.Decode(dec, &block); err != nil {
		return nil, nil, errors.Wrap(err, "unable to decode uni-bark message")
	}
	upd, pt = block.R, block.Message
	return
}
