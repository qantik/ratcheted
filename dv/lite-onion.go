// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package dv

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/pkg/errors"

	"github.com/qantik/ratcheted/primitives"
	"github.com/qantik/ratcheted/primitives/encryption"
)

// liteOnion is the ARCAD unidirectional subroutine handler.
type liteOnion struct {
	otae encryption.Authenticated
	enc  encryption.Symmetric
}

// liteOnionMessage bundles the plaintext material.
type liteOnionMessage struct {
	S   []byte // S designates the new receiver state.
	Msg []byte // Msg is the plaintext.
}

// liteOnionCiphertext bundles the onion ciphertext array.
type liteOnionCiphertext struct {
	CT [][]byte
}

// init creates fresh lite-onion sender and receiver states.
func (o liteOnion) init() (s, r []byte, err error) {
	sk := make([]byte, 16)
	if _, err := rand.Read(sk); err != nil {
		return nil, nil, errors.Wrap(err, "unable to poll random source")
	}
	return sk, sk, nil
}

// send implements the lite-onion send procedure.
func (o liteOnion) send(s [][]byte, hk, ad, msg []byte) (upd, ct []byte, err error) {
	sk, _, err := o.init()
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to create new lite-onion states")
	}

	n := len(s)

	k := make([]byte, 16)
	ks := make([][]byte, n)

	for i := 0; i < n; i++ {
		tmp := make([]byte, 16)
		if _, err := rand.Read(tmp); err != nil {
			return nil, nil, errors.Wrap(err, "unable to poll random source")
		}
		k = primitives.Xor(k, tmp)
		ks[i] = tmp
	}

	pt, err := primitives.Encode(liteOnionMessage{S: sk, Msg: msg})
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to encode onion message")
	}

	c := make([][]byte, n+1)
	c[n], err = o.enc.Encrypt(k, pt)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to encrypt plaintext")
	}

	for i := n - 1; i >= 0; i-- {
		ad = primitives.Digest(sha256.New(), hk, ad, c[i+1])
		fmt.Println("s", s[i], ad, ks[i])
		c[i], err = o.otae.Encrypt(s[i], ks[i], ad)
		if err != nil {
			return nil, nil, errors.Wrap(err, "unable to encrypt message")
		}
	}

	ct, err = primitives.Encode(liteOnionCiphertext{CT: c})
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to encode ciphertext")
	}
	return sk, ct, nil
}

// receive invokes the lite-onion receive routine.
func (o liteOnion) receive(s [][]byte, hk, ad, ct []byte) (upd, msg []byte, err error) {
	var c liteOnionCiphertext
	if err := primitives.Decode(ct, &c); err != nil {
		return nil, nil, errors.Wrap(err, "unable to decode lite-onion ciphertext")
	}

	n := len(s)

	k := make([]byte, 16)

	for i := n - 1; i >= 0; i-- {
		ad = primitives.Digest(sha256.New(), hk, ad, c.CT[i+1])

		fmt.Println("r", s[i], ad, c.CT[i])
		tmp, err := o.otae.Decrypt(s[i], c.CT[i], ad)
		if err != nil {
			return nil, nil, errors.Wrap(err, "unable to decrypt lite-onion ciphertext")
		}

		k = primitives.Xor(k, tmp)
	}

	pt, err := o.enc.Decrypt(k, c.CT[n])
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to decrypt lite-onion ciphertext")
	}

	var m liteOnionMessage
	if err = primitives.Decode(pt, &m); err != nil {
		return nil, nil, errors.Wrap(err, "unable to decode lite-onion message")
	}
	return m.S, m.Msg, nil
}
