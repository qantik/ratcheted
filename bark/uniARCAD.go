// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package bark

import (
	"github.com/pkg/errors"

	"github.com/qantik/ratcheted/primitives"
	"github.com/qantik/ratcheted/primitives/encryption"
	"github.com/qantik/ratcheted/primitives/signature"
)

// Uni is the uniARCAD object handler.
type uniARCAD struct {
	sc *signcryption
}

// sender is the uniARCAD sender state.
type sender struct {
	SKS, PKR []byte // SKS, PKR are the signcryption encryption and signature keys.
}

// receiver is the uniARCAD receiver state.
type receiver struct {
	SKR, PKS []byte // SKR, PKS are the signcryption decryption and verification keys.
}

// uniBlock bundles the updated receiver state with a plaintext message.
type uniBlock struct {
	R, Message []byte
}

// NewUniARCAD returns a fresh uniARCAD instance for a given public-key encryption
// scheme and a digital signature scheme.
func NewUniARCAD(enc encryption.Asymmetric, sig signature.Signature) *uniARCAD {
	return &uniARCAD{sc: &signcryption{encryption: enc, signature: sig}}
}

// Init generates initialized the uniARCAD protocol, returning
// both a sender and receiver state.
func (u uniARCAD) Init() (s, r []byte, err error) {
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

// Send invokes the uniARCAD send routine for a given sender state, associated data
// and a plaintext. Ratchet indicates whether the sender state is updated or not.
func (u uniARCAD) Send(state, ad, pt []byte, ratchet bool) (upd, ct []byte, err error) {
	var s sender
	if err := primitives.Decode(state, &s); err != nil {
		return nil, nil, errors.Wrap(err, "unable to decode uni-bark sender state")
	}

	var us, ur []byte
	if ratchet {
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

// Receive invokes the uniARCAD receive routine for a given receiver state,
// associated data and a ciphertext.
func (u uniARCAD) Receive(str, ad, ct []byte) (upd, pt []byte, err error) {
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
