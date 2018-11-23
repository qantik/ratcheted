// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package dratch

import (
	"crypto/elliptic"
	"encoding/json"

	"github.com/pkg/errors"
	"github.com/qantik/ratcheted/primitives/encryption"
)

const keySize = 16

type DRatch struct {
	pp  *prfPRNG
	fsa *fsAEAD
	cka *cka
}

// User designates a participant in the protocol that can both send and receive
// messages. It has to be passed as an argument to both the send and receive routines.
type User struct {
	Gamma []byte // Gamma is CKA state.
	T     []byte // T is the current CKA message.
	I     int    // I is the current user epoch.

	V map[int][]byte // V contains all FS-AEAD (send, receive) states.
}

// NewDRatch returns a fresh double ratchet instance for a given AEAD scheme.
func NewDRatch(aead encryption.Authenticated) *DRatch {
	return &DRatch{
		pp:  &prfPRNG{},
		fsa: &fsAEAD{aead: aead, pp: &prfPRNG{}},
		cka: &cka{curve: elliptic.P256()},
	}
}

func (d DRatch) Init() (a, b []byte, err error) {
	root, err := d.pp.generate()
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to initialize prf-prng")
	}
	root, k, err := d.pp.up(keySize, root, nil)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to poll prf-prng")
	}

	_, va, err := d.fsa.generate(k)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to generate fs-aead state")
	}
	_, vb, err := d.fsa.generate(k)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to generate fs-aead state")
	}

	ga, gb, err := d.cka.generate()
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to generate cka states")
	}

	alice := User{Gamma: ga, T: nil, I: 0, V: map[int][]byte{0: va}}
	bob := User{Gamma: gb, T: nil, I: 0, V: map[int][]byte{0: vb}}
	a, err = json.Marshal(&alice)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to marshal user state")
	}
	b, err = json.Marshal(&bob)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to marshal user state")
	}
	return
}
