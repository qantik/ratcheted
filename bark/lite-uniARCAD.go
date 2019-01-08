// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package bark

import (
	"crypto/rand"

	"github.com/pkg/errors"

	"github.com/qantik/ratcheted/primitives"
	"github.com/qantik/ratcheted/primitives/encryption"
)

// Fix symmetric lite uniBARK key (state) size at 128 bits.
const liteUniKeySize = 16

// LiteUniARCAD implements the lite-uniARCAD protocol.
type LiteUniARCAD struct {
	encryption encryption.Authenticated
}

// liteUniCiphertext bundles lite uniBARK plaintext material.
type liteUniBlock struct {
	Key, Message []byte
}

// NewLiteUniARCAD creates a fresh LiteUni instance for a given authenticated encryption scheme.
func NewLiteUniARCAD(encryption encryption.Authenticated) *LiteUniARCAD {
	return &LiteUniARCAD{encryption: encryption}
}

// Init returns fresh lite-uniARCAD sender and receiver states.
func (l LiteUniARCAD) Init() (s, r []byte, err error) {
	s = make([]byte, liteUniKeySize)
	if _, err := rand.Read(s); err != nil {
		return nil, nil, err
	}

	r = make([]byte, liteUniKeySize)
	copy(r, s)

	return
}

// Send invokes the lite-uniARCAD send routine for a given sender state, associated data
// and a plaintext. Ratchet indicates whether the sender state is updated or not.
func (l LiteUniARCAD) Send(state, ad, pt []byte, ratchet bool) (upd, ct []byte, err error) {
	if ratchet {
		upd = make([]byte, liteUniKeySize)
		if _, err := rand.Read(upd); err != nil {
			return nil, nil, err
		}
	}

	block, err := primitives.Encode(&liteUniBlock{Key: upd, Message: pt})
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to encode lite-bark message")
	}

	ct, err = l.encryption.Encrypt(state, block, ad)
	return
}

// Receive invokes the lite-uniARCAD receive routine for a given receiver state,
// associated data and a ciphertext.
func (l LiteUniARCAD) Receive(state, ad, ct []byte) (upd, pt []byte, err error) {
	dec, err := l.encryption.Decrypt(state, ct, ad)
	if err != nil {
		return nil, nil, err
	}

	var block liteUniBlock
	if err := primitives.Decode(dec, &block); err != nil {
		return nil, nil, errors.Wrap(err, "unable to decode lite-bark message")
	}
	upd, pt = block.Key, block.Message
	return
}
