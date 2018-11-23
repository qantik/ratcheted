// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package dratch

import (
	"encoding/json"
	"strconv"

	"github.com/pkg/errors"

	"github.com/qantik/ratcheted/primitives/encryption"
)

const fsKeySize = 16

// fsAEAD implements the forward-secure authenticated encryption with associated data
// scheme based on a AEAD scheme.
type fsAEAD struct {
	aead encryption.Authenticated
	pp   *prfPRNG
}

// fsaSender designates the FS-AEAD sender state.
type fsaSender struct {
	W []byte // W is the PRG key.
	I int    // I is the number of sent messages.
}

// fsaReceiver designates the FS-AEAD receiver state.
type fsaReceiver struct {
	W []byte         // W is the PRG key.
	I int            // I is the number of received messages.
	D map[int][]byte // D records skipped AEAD keys.
}

// fsaCiphertext bundles the actual ciphertext and the sender epoch.
type fsaCiphertext struct {
	C []byte // C is the ciphertext.
	I int    // I is the number of sent messages.
}

// generate creates a fresh FS-AEAD sender and receiver states.
func (f fsAEAD) generate() (s, r []byte, err error) {
	k, err := f.pp.generate()
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to create fs-aead state")
	}
	s, err = json.Marshal(&fsaSender{W: k, I: 0})
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to marshal fs-aead sender state")
	}
	r, err = json.Marshal(&fsaReceiver{W: k, I: 0, D: map[int][]byte{}})
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to marshal fs-aead receiver state")
	}
	return
}

// send encrypts and authenticates the message and associated data and updates
// FS-AEAD sender state.
func (f fsAEAD) send(sender, msg, ad []byte) (upd, ct []byte, err error) {
	var s fsaSender
	if err := json.Unmarshal(sender, &s); err != nil {
		return nil, nil, errors.Wrap(err, "unable to unmarshal fs-aead sender state")
	}
	s.I++

	w, k, err := f.pp.up(fsKeySize, s.W, nil)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to update fs-aead sender state")
	}
	s.W = w

	h := append([]byte(strconv.Itoa(s.I)), ad...)
	e, err := f.aead.Encrypt(k, msg, h)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to encrypt message")
	}

	ct, err = json.Marshal(&fsaCiphertext{C: e, I: s.I})
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to marshal fs-aead ciphertext")
	}
	upd, err = json.Marshal(&s)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to marshal fs-aead sender state")
	}
	return
}

// receive decrypt and authenticates the ciphertext and associated data and
// updates the FS-AEAD receiver state.
func (f fsAEAD) receive(receiver, ct, ad []byte) (upd, msg []byte, err error) {
	var r fsaReceiver
	if err := json.Unmarshal(receiver, &r); err != nil {
		return nil, nil, errors.Wrap(err, "unable to unmarshal fs-aead receiver state")
	}
	var c fsaCiphertext
	if err := json.Unmarshal(ct, &c); err != nil {
		return nil, nil, errors.Wrap(err, "unable to unmarshal fs-aead ciphertext")
	}

	var w, k []byte

	// try-skipped
	k = r.D[c.I]
	r.D[c.I] = nil

	if k == nil || len(k) == 0 {
		// skip
		for r.I < c.I-1 {
			r.I++
			w, k, err = f.pp.up(fsKeySize, r.W, nil)
			if err != nil {
				return nil, nil, errors.Wrap(err, "unable to poll prf-prng")
			}
			r.W = w
			r.D[c.I-1] = k
		}
		w, k, err = f.pp.up(fsKeySize, r.W, nil)
		if err != nil {
			return nil, nil, errors.Wrap(err, "unable to poll prf-prng")
		}
		r.I = c.I
		r.W = w
	}

	h := append([]byte(strconv.Itoa(c.I)), ad...)
	msg, err = f.aead.Decrypt(k, c.C, h)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to decrypt ciphertext")
	}
	upd, err = json.Marshal(&r)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to marshal fs-aead receiver state")
	}
	return
}
