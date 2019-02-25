// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package dv

import (
	"crypto/sha256"
	"fmt"
	"strconv"

	"github.com/alecthomas/binary"

	"github.com/pkg/errors"

	"github.com/qantik/ratcheted/primitives"
	"github.com/qantik/ratcheted/primitives/encryption"
	"github.com/qantik/ratcheted/primitives/signature"
)

// HybridARCAD implements the hybrid-ARCAD protocol.
type HybridARCAD struct {
	arcad, lite *ARCAD
}

// HybridUser designates a hybrid-ARCAD user state.
type HybridUser struct {
	stARCAD *ARCADUser
	stLite  map[string]*ARCADUser

	snd, rec int
	ctr      map[int]int
}

// hybridMessage bundles the plaintext material in the during flagged periods.
type hybridMessage struct {
	State []byte
	Msg   []byte
}

// hybridAssociated bundles associated data material.
type hybridAssociated struct {
	AD   []byte
	E, C int
}

// hybridCiphertext bundles the ciphertext material.
type hybridCiphertext struct {
	CT   []byte
	E, C int
}

// NewHybridARCAD creates a fresh hybrid-ARCAD instance.
func NewHybridARCAD(
	signature signature.Signature,
	asymmetric encryption.Asymmetric,
	symmetric encryption.Symmetric,
	otae encryption.Authenticated) *HybridARCAD {

	return &HybridARCAD{
		arcad: NewARCAD(signature, asymmetric, symmetric),
		lite:  NewLiteARCAD(otae, symmetric),
	}
}

// Init intializes the hybrid-ARCAD protocol and returns two user states.
func (h HybridARCAD) Init() (alice, bob *HybridUser, err error) {
	as, ar, err := h.arcad.Init()
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to create fresh ARCAD states")
	}
	ls, lr, err := h.lite.Init()
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to create fresh lite-ARCAD states")
	}

	alice = &HybridUser{
		stARCAD: as,
		stLite:  map[string]*ARCADUser{index(0, 0): ls},
		snd:     0, rec: -1, ctr: map[int]int{0: 0},
	}
	bob = &HybridUser{
		stARCAD: ar,
		stLite:  map[string]*ARCADUser{index(0, 0): lr},
		snd:     -1, rec: 0, ctr: map[int]int{0: 0},
	}
	return
}

// Send invokes the hybrid-ARCAD send routine.
func (h HybridARCAD) Send(user *HybridUser, ad, msg []byte) ([]byte, error) {
	var ct []byte
	var e, c int

	if int(ad[0]) == 1 {
		fmt.Println("===============")
		if user.snd < user.rec {
			e, c = user.rec+1, 0
		} else {
			e, c = user.snd, user.ctr[e]+1
		}

		s, r, err := h.lite.Init()
		if err != nil {
			return nil, errors.Wrap(err, "unable to create fresh lite-ARCAD states")
		}
		user.stLite[index(e, c)] = s

		st, err := binary.Marshal(r)
		if err != nil {
			return nil, errors.Wrap(err, "unable to marshal lite-ARCAD receiver state")
		}

		pt, err := binary.Marshal(&hybridMessage{State: st, Msg: msg})
		if err != nil {
			return nil, errors.Wrap(err, "unable to marshal hybrid-ARCAD message")
		}

		ba, err := binary.Marshal(&hybridAssociated{AD: ad, E: e, C: c})
		if err != nil {
			return nil, errors.Wrap(err, "unable to marshal hybrid-ARCAD associated data")
		}

		ct, err = h.arcad.Send(user.stARCAD, ba, pt)
		if err != nil {
			return nil, errors.Wrap(err, "unable to encrypt plaintext")
		}
		user.snd, user.ctr[user.snd] = e, c
	} else {
		if user.snd >= user.rec {
			e = user.snd
		} else {
			e = user.rec
		}
		c = user.ctr[e]

		ba, err := binary.Marshal(&hybridAssociated{AD: ad, E: e, C: c})
		if err != nil {
			return nil, errors.Wrap(err, "unable to marshal hybrid-ARCAD associated data")
		}

		ct, err = h.lite.Send(user.stLite[index(e, c)], ba, msg)
		if err != nil {
			return nil, errors.Wrap(err, "unable to encrypt plaintext")
		}
	}

	// Clean-up states.
	for e := 0; e < user.snd && e < user.rec; e++ {
		for c := 0; c < user.ctr[user.snd] && c < user.ctr[user.rec]; c++ {
			// fmt.Println("************", e, c)
			delete(user.stLite, index(e, c))
		}
	}
	for e := 0; e < user.snd && e < user.rec; e++ {
		delete(user.ctr, e)
	}

	return binary.Marshal(&hybridCiphertext{CT: ct, E: e, C: c})
}

// Receive invokes the hybrid-ARCAD receive routine.
func (h HybridARCAD) Receive(user *HybridUser, ad, ct []byte) ([]byte, error) {
	var cipher hybridCiphertext
	if err := binary.Unmarshal(ct, &cipher); err != nil {
		return nil, errors.Wrap(err, "unable to unmarshal hybrid-ARCAD ciphertext")
	}

	ba, err := binary.Marshal(&hybridAssociated{AD: ad, E: cipher.E, C: cipher.C})
	if err != nil {
		return nil, errors.Wrap(err, "unable to marshal hybrid-ARCAD associated data")
	}

	var m []byte

	if int(ad[0]) == 1 {
		pt, err := h.arcad.Receive(user.stARCAD, ba, cipher.CT)
		if err != nil {
			return nil, errors.Wrap(err, "unable to decrypt ciphertext")
		}

		var msg hybridMessage
		if err := binary.Unmarshal(pt, &msg); err != nil {
			return nil, errors.Wrap(err, "unable to unmarshal hybrid-ARCAD message")
		}
		m = msg.Msg

		var st ARCADUser
		if err := binary.Unmarshal(msg.State, &st); err != nil {
			return nil, errors.Wrap(err, "unable to unmarshal hybrid-ARCAD state")
		}

		user.stLite[index(cipher.E, cipher.C)] = &st
		user.rec, user.ctr[cipher.E] = cipher.E, cipher.C
	} else {
		pt, err := h.lite.Receive(user.stLite[index(cipher.E, cipher.C)], ba, cipher.CT)
		if err != nil {
			return nil, errors.Wrap(err, "unable to decrypt ciphertext")
		}
		m = pt
	}

	// Clean-up states.
	for e := 0; e < user.snd && e < user.rec; e++ {
		for c := 0; c < user.ctr[user.snd] && c < user.ctr[user.rec]; c++ {
			delete(user.stLite, index(e, c))
		}
	}
	for e := 0; e < user.snd && e < user.rec; e++ {
		delete(user.ctr, e)
	}

	return m, nil
}

// index creates a hashable map index out of two integers.
func index(a, b int) string {
	return string(primitives.Digest(
		sha256.New(),
		[]byte(strconv.Itoa(a)),
		[]byte(strconv.Itoa(b)),
	))
}
