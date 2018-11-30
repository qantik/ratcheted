// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package dratch

import (
	"crypto/elliptic"
	"strconv"

	"github.com/pkg/errors"

	"github.com/qantik/ratcheted/primitives"
	"github.com/qantik/ratcheted/primitives/encryption"
)

const keySize = 16

type DRatch struct {
	pp  *prfPRNG
	fsa *fsAEAD
	cka *cka
}

// dratchCiphertext bundles ciphertext material.
type dratchCiphertext struct {
	I int    // I is the epoch of the sender.
	T []byte // T is the CKA message.

	C []byte // C is the actual ciphertext.
}

// User designates a participant in the protocol that can both send and receive
// messages. It has to be passed as an argument to both the send and receive routines.
type User struct {
	Gamma []byte // Gamma is CKA state.
	T     []byte // T is the current CKA message.
	I     int    // I is the current user epoch.
	Root  []byte // Root is the current PRF-PRNG key.

	V map[int][]byte // V contains all FS-AEAD (send, receive) states.

	name string
}

// NewDRatch returns a fresh double ratchet instance for a given AEAD scheme.
func NewDRatch(aead encryption.Authenticated) *DRatch {
	return &DRatch{
		pp:  &prfPRNG{},
		fsa: &fsAEAD{aead: aead, pp: &prfPRNG{}},
		cka: &cka{curve: elliptic.P256()},
	}
}

func (d DRatch) Init() (alice, bob *User, err error) {
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

	alice = &User{Gamma: ga, T: nil, I: 0, V: map[int][]byte{0: va}, name: "alice"}
	bob = &User{Gamma: gb, T: nil, I: 0, V: map[int][]byte{0: vb}, name: "bob"}
	return
}

func (d DRatch) Send(user *User, msg []byte) ([]byte, error) {
	if (user.name == "alice" && user.I%2 == 0) || (user.name == "bob" && user.I%2 == 1) {
		user.V[user.I-1] = nil

		user.I++
		gamma, t, i, err := d.cka.send(user.Gamma)
		if err != nil {
			return nil, errors.Wrap(err, "unable create cka message")
		}
		user.Gamma = gamma
		user.T = t

		root, k, err := d.pp.up(16, user.Root, i)
		if err != nil {
			return nil, errors.Wrap(err, "unable to poll prf-prng")
		}
		user.Root = root

		v, _, err := d.fsa.generate(k)
		if err != nil {
			return nil, errors.Wrap(err, "unable to create fresh fs-aead sender state")
		}
		user.V[user.I] = v
	}

	ad := append([]byte(strconv.Itoa(user.I)), user.T...)
	v, c, err := d.fsa.send(user.V[user.I], msg, ad)
	if err != nil {
		return nil, errors.Wrap(err, "unable to fs-aead encrypt message")
	}
	user.V[user.I] = v

	ct, err := primitives.Encode(&dratchCiphertext{I: user.I, T: user.T, C: c})
	if err != nil {
		return nil, errors.Wrap(err, "unable to encode dratch ciphertext")
	}
	return ct, nil
}

func (d DRatch) Receive(user *User, ct []byte) ([]byte, error) {
	var c dratchCiphertext
	if err := primitives.Decode(ct, &c); err != nil {
		return nil, errors.Wrap(err, "unable to decode dratch ciphertext")
	}
	ad := append([]byte(strconv.Itoa(c.I)), c.T...)

	if (user.name == "alice" && c.I <= user.I && c.I%2 == 0) ||
		(user.name == "bob" && c.I <= user.I && c.I%2 == 1) {

		v, msg, err := d.fsa.receive(user.V[c.I], c.C, ad)
		if err != nil {
			return nil, errors.Wrap(err, "unable to fs-aead decrypt message")
		}
		user.V[c.I] = v

		return msg, nil
	} else if (user.name == "alice" && c.I == user.I+1 && user.I%2 == 1) ||
		(user.name == "bob" && c.I == user.I+1 && user.I%2 == 0) {

		user.I++

		gamma, i, err := d.cka.receive(user.Gamma, c.T)
		if err != nil {
			return nil, errors.Wrap(err, "unable to receive cka message")
		}
		user.Gamma = gamma

		root, k, err := d.pp.up(16, user.Root, i)
		if err != nil {
			return nil, errors.Wrap(err, "unable to poll prf-prng")
		}
		user.Root = root

		_, v, err := d.fsa.generate(k)
		if err != nil {
			return nil, errors.Wrap(err, "unable to create fresh fs-aead receiver state")
		}
		user.V[c.I] = v

		v, msg, err := d.fsa.receive(user.V[c.I], c.C, ad)
		if err != nil {
			return nil, errors.Wrap(err, "unable to fs-aead decrypt message")
		}
		user.V[c.I] = v

		return msg, nil
	}
	return nil, errors.New("user epochs are out-of-sync")
}
