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

// LiteUni implements the lite uniBARK protocol.
type LiteUni struct {
	encryption encryption.Authenticated
}

// liteUniCiphertext bundles lite uniBARK plaintext material.
type liteUniBlock struct {
	Key, Message []byte
}

// NewLiteUni creates a fresh LiteUni instance with a given authenticated encryption scheme.
func NewLiteUni(encryption encryption.Authenticated) *LiteUni {
	return &LiteUni{encryption: encryption}
}

// Init returns fresh lite uniBARK sender and receiver states.
func (l LiteUni) Init() (s, r []byte, err error) {
	s = make([]byte, liteUniKeySize)
	if _, err := rand.Read(s); err != nil {
		return nil, nil, err
	}

	r = make([]byte, liteUniKeySize)
	copy(r, s)

	return
}

// Send creates a new state and encrypts it for transmission to another participant.
func (l LiteUni) Send(state, ad, pt []byte, simple bool) (upd, ct []byte, err error) {
	if !simple {
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

// Receive decrypts the ciphertext to get the updated state.
func (l LiteUni) Receive(state, ad, ct []byte) (upd, pt []byte, err error) {
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
