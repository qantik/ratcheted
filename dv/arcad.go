// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package dv

import (
	"crypto/rand"

	"github.com/alecthomas/binary"

	"github.com/pkg/errors"

	"github.com/qantik/ratcheted/primitives/encryption"
	"github.com/qantik/ratcheted/primitives/signature"
)

type unid interface {
	init() ([]byte, []byte, error)
	send(states [][]byte, hk, ad, msg []byte) ([]byte, []byte, error)
	receive(states [][]byte, hk, ad, ct []byte) ([]byte, []byte, error)
}

// ARCAD designates the object handler of the ARCAD protocol.
type ARCAD struct {
	unid unid
}

// ARCADUser designates a ARCAD user state.
type ARCADUser struct {
	Hk               []byte
	Sender, Receiver [][]byte
}

// func (u ARCADUser) Size() int {
// 	return 0
// }

// arcadMessage bundles plaintext material.
type arcadMessage struct {
	S, Msg []byte
	N      int
}

// arcadCiphertext bundles ciphertext material.
type arcadCiphertext struct {
	C []byte
	N int
}

var hashKeySize = 16

// NewARCAD returns a fresh ARCAD instance for a given signature scheme,
// a public-key encryption scheme and a symmetric encryption scheme.
func NewARCAD(
	signature signature.Signature,
	asymmetric encryption.Asymmetric,
	symmetric encryption.Symmetric) *ARCAD {

	return &ARCAD{unid: &onion{&signcryption{asymmetric, signature}, symmetric}}
}

// NewLiteARCAD return a fresh lite-ARCAD instance.
func NewLiteARCAD(otae encryption.Authenticated, symmetric encryption.Symmetric) *ARCAD {
	return &ARCAD{unid: &liteOnion{otae, symmetric}}
}

// Init initializes the ARCAD protocol and returns two user states.
func (a ARCAD) Init() (alice, bob Uuser, err error) {
	sa, ra, err := a.unid.init()
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to create new onion states")
	}

	sb, rb, err := a.unid.init()
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to create new onion states")
	}

	hk := make([]byte, hashKeySize)
	if _, err := rand.Read(hk); err != nil {
		return nil, nil, errors.Wrap(err, "unable to poll random source")
	}
	alice = &ARCADUser{Hk: hk, Sender: [][]byte{sa}, Receiver: [][]byte{rb}}
	bob = &ARCADUser{Hk: hk, Sender: [][]byte{sb}, Receiver: [][]byte{ra}}
	return
}

// Send invokes the ARCAD send routine.
func (a ARCAD) Send(user Uuser, ad, msg []byte) (ct []byte, err error) {
	s, r, err := a.unid.init()
	if err != nil {
		return nil, errors.Wrap(err, "unable to create new onion states")
	}

	u := user.(*ARCADUser)

	u.Receiver = append(u.Receiver, r)

	i := 0
	for j, s := range u.Sender {
		if s != nil {
			i = j
			break
		}
	}
	pt, err := binary.Marshal(arcadMessage{S: s, Msg: msg, N: len(u.Sender) - i - 1})
	if err != nil {
		return nil, errors.Wrap(err, "unable to encode arcad message")
	}

	st, c, err := a.unid.send(u.Sender[i:], u.Hk, ad, pt)
	if err != nil {
		return nil, errors.Wrap(err, "unable to onion encrypt message")
	}
	u.Sender[len(u.Sender)-1] = st

	for i := 0; i < len(u.Sender)-1; i++ {
		u.Sender[i] = nil
	}

	ct, err = binary.Marshal(arcadCiphertext{C: c, N: len(u.Sender[i:])})
	if err != nil {
		return nil, errors.Wrap(err, "unable to encode arcad ciphertext")
	}
	return
}

// receive invokes the ARCAD receive routine.
func (a ARCAD) Receive(user Uuser, ad, ct []byte) (msg []byte, err error) {
	var c arcadCiphertext
	if err := binary.Unmarshal(ct, &c); err != nil {
		return nil, errors.Wrap(err, "unable to decode arcad ciphertext")
	}

	u := user.(*ARCADUser)

	i := 0
	for j, s := range u.Receiver {
		if s != nil {
			i = j
			break
		}
	}

	st, pt, err := a.unid.receive(u.Receiver[i:i+c.N], u.Hk, ad, c.C)
	if err != nil {
		return nil, errors.Wrap(err, "unable to onion decrypt ciphertext")
	}

	var m arcadMessage
	if err = binary.Unmarshal(pt, &m); err != nil {
		return nil, errors.Wrap(err, "unable to decode arcad message")
	}
	u.Sender = append(u.Sender, m.S)

	for j := i; j < i+c.N; j++ {
		u.Receiver[j] = nil
	}
	u.Receiver[i+c.N-1] = st

	return m.Msg, nil
}
