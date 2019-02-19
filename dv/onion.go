// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package dv

import (
	"crypto/rand"
	"crypto/sha256"

	"github.com/pkg/errors"

	"github.com/qantik/ratcheted/primitives"
	"github.com/qantik/ratcheted/primitives/encryption"
)

// onion is the ARCAD unidirectional subroutine handler.
type onion struct {
	sc  *signcryption
	enc encryption.Symmetric
}

// onionSender is the onion sender state.
type onionSender struct {
	SKS, PKR []byte
}

// onionReceiver is the onion receiver state.
type onionReceiver struct {
	SKR, PKS []byte
}

// onionMessage bundles the plaintext material.
type onionMessage struct {
	S   []byte // S designates the new receiver state.
	Msg []byte // Msg is the plaintext.
}

// onionCiphertext bundles the onion ciphertext array.
type onionCiphertext struct {
	CT [][]byte
}

// init creates fresh onion sender and receiver states.
func (o onion) init() (s, r []byte, err error) {
	sks, skr, err := o.sc.generateSignKeys()
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to generate signcryption signature keys")
	}

	pks, pkr, err := o.sc.generateCipherKeys()
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to generate signcryption cipher keys")
	}

	s, err = primitives.Encode(onionSender{SKS: sks, PKR: pkr})
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to encode onion sender")
	}
	r, err = primitives.Encode(onionReceiver{SKR: skr, PKS: pks})
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to encode onion receiver")
	}
	return
}

// send implements the onion send procedure.
func (o onion) send(s [][]byte, hk, ad, msg []byte) (upd, ct []byte, err error) {
	us, ur, err := o.init()
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to create new onion states")
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

	pt, err := primitives.Encode(onionMessage{S: ur, Msg: msg})
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to encode onion message")
	}

	c := make([][]byte, n+1)
	c[n], err = o.enc.Encrypt(k, pt)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to encrypt ciphertext")
	}

	for i := n - 1; i >= 0; i-- {
		ad = primitives.Digest(sha256.New(), hk, ad, c[i])

		var st onionSender
		if err = primitives.Decode(s[i], &st); err != nil {
			return nil, nil, errors.Wrap(err, "unable to decode onion sender state")
		}

		c[i], err = o.sc.signcrypt(st.SKS, st.PKR, ad, ks[i])
		if err != nil {
			return nil, nil, errors.Wrap(err, "unable to signcrypt message")
		}
	}

	ct, err = primitives.Encode(onionCiphertext{CT: c})
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to encode ciphertext")
	}
	return us, ct, nil
}

// receive invokes the onion receive routine.
func (o onion) receive(s [][]byte, hk, ad, ct []byte) (upd, msg []byte, err error) {
	var c onionCiphertext
	if err := primitives.Decode(ct, &c); err != nil {
		return nil, nil, errors.Wrap(err, "unable to decode onion ciphertext")
	}

	n := len(s)

	k := make([]byte, 16)

	for i := n - 1; i >= 0; i-- {
		var st onionReceiver
		if err := primitives.Decode(s[i], &st); err != nil {
			return nil, nil, errors.Wrap(err, "unable to decode onion receiver state")
		}

		ad = primitives.Digest(sha256.New(), hk, ad, c.CT[i+1])

		tmp, err := o.sc.unsigncrypt(st.SKR, st.PKS, ad, c.CT[i])
		if err != nil {
			return nil, nil, errors.Wrap(err, "unable to decrypt onion ciphertext")
		}

		k = primitives.Xor(k, tmp)
	}

	pt, err := o.enc.Decrypt(k, c.CT[n])
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to decrypt onion ciphertext")
	}

	var m onionMessage
	if err = primitives.Decode(pt, &m); err != nil {
		return nil, nil, errors.Wrap(err, "unable to decode onion message")
	}
	return m.S, m.Msg, nil
}
