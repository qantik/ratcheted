// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package dratch

import (
	"crypto/elliptic"
	"crypto/rand"

	"github.com/pkg/errors"
	"github.com/qantik/ratcheted/primitives"
)

// cka implements the continuous key agreement scheme proposed in the paper. The
// implementation follows the optimized version based on the Decisional
// Hellman assumption. Note, that this protocol is synchronous, i.e. a participant
// must receive a message after sending one or send one after receiving one.
type cka struct {
	curve elliptic.Curve
}

// ckaState defines a user state in the CKA protocol defined by a key.
type ckaState struct {
	Key []byte // Key is the currently established public or private key of a user.

	// Indicates which action (send=true, receive=false) can be performed with this state.
	Role bool
}

// generate creates two CKA user states (sa, sb) where sa is the state that has
// to send the first message.
func (c cka) generate() (sa, sb []byte, err error) {
	private, x, y, err := elliptic.GenerateKey(c.curve, rand.Reader)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to generate cka key pair")
	}

	pk := elliptic.Marshal(c.curve, x, y)
	sk := private

	sa, err = primitives.Encode(&ckaState{Key: pk, Role: true})
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to encode cka state")
	}
	sb, err = primitives.Encode(&ckaState{Key: sk, Role: false})
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to encode cka state")
	}
	return
}

// send creates a fresh CKA key and a message for the counterpart to regenerate this key,
// it also updates the sender state.
func (c cka) send(state []byte) (upd, msg, key []byte, err error) {
	var s ckaState
	if err := primitives.Decode(state, &s); err != nil {
		return nil, nil, nil, errors.Wrap(err, "unable to decode cka state")
	}
	if s.Role == false {
		return nil, nil, nil, errors.Wrap(err, "state is in receiving mode")
	}

	hx, hy := elliptic.Unmarshal(c.curve, s.Key)
	if hx == nil {
		return nil, nil, nil, errors.Wrap(err, "unable unmarshal cka public key")
	}

	x, _, _, err := elliptic.GenerateKey(c.curve, rand.Reader)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "unable to create random scalar")
	}
	ix, iy := c.curve.ScalarMult(hx, hy, x)
	key = elliptic.Marshal(c.curve, ix, iy)
	tx, ty := c.curve.ScalarBaseMult(x)
	msg = elliptic.Marshal(c.curve, tx, ty)

	upd, err = primitives.Encode(&ckaState{Key: x, Role: false})
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "unable to encode cka state")
	}
	return
}

// receive extracts the by the sender established CKA key and updates the receiver state.
func (c cka) receive(state, msg []byte) (upd, key []byte, err error) {
	var s ckaState
	if err := primitives.Decode(state, &s); err != nil {
		return nil, nil, errors.Wrap(err, "unable to decode cka state")
	}
	if s.Role == true {
		return nil, nil, errors.Wrap(err, "state is in sending mode")
	}

	hx, hy := elliptic.Unmarshal(c.curve, msg)
	if hx == nil {
		return nil, nil, errors.Wrap(err, "unable unmarshal cka msg")
	}
	ix, iy := c.curve.ScalarMult(hx, hy, s.Key)
	key = elliptic.Marshal(c.curve, ix, iy)

	upd, err = primitives.Encode(&ckaState{Key: msg, Role: true})
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to encode cka state")
	}
	return
}
