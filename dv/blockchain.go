// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package dv

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"

	"github.com/alecthomas/binary"

	"github.com/pkg/errors"

	"github.com/qantik/ratcheted/primitives"
)

// BlockchainARCAD implements the blockchain-ARCAD protocol.
type BlockchainARCAD struct {
	arcad Protocol
}

// BlockchainUser designates a blockchain-ARCAD user state.
type BlockchainUser struct {
	st Uuser

	hk []byte

	hsnd, hrec []byte
	asnd       [][]byte
	arec       int
}

// hybridAssociated bundles associated data material.
type blockchainAssociated struct {
	AD         []byte
	Hsent, Ack []byte
}

// hybridCiphertext bundles the ciphertext material.
type blockchainCiphertext struct {
	CT         []byte
	Hsent, Ack []byte
}

// NewBlockchainARCAD returns a fresh blockchain-ARCAD instance.
func NewBlockchainARCAD(arcad Protocol) *BlockchainARCAD {
	return &BlockchainARCAD{arcad: arcad}
}

// Init initializes the blockchain-ARCAD protocol and returns two user states.
func (b BlockchainARCAD) Init() (alice, bob Uuser, err error) {
	s, r, err := b.arcad.Init()
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to initialize arcad protocol")
	}

	hk := make([]byte, hashKeySize)
	if _, err := rand.Read(hk); err != nil {
		return nil, nil, errors.Wrap(err, "unable to poll random source")
	}

	alice = &BlockchainUser{
		st:   s,
		hk:   hk,
		hsnd: nil, hrec: nil,
		asnd: [][]byte{}, arec: 0,
	}
	bob = &BlockchainUser{
		st:   r,
		hk:   hk,
		hsnd: nil, hrec: nil,
		asnd: [][]byte{}, arec: 0,
	}
	return
}

// Send invokes the blockchain-ARCAD send routine.
func (b BlockchainARCAD) Send(user Uuser, ad, msg []byte) ([]byte, error) {
	u := user.(*BlockchainUser)

	ack := u.hrec
	if u.arec == 0 {
		ack = nil
	}

	ba, err := binary.Marshal(&blockchainAssociated{AD: ad, Hsent: u.hsnd, Ack: ack})
	if err != nil {
		return nil, errors.Wrap(err, "unable to marshal associated data")
	}

	ct, err := b.arcad.Send(u.st, ba, msg)
	if err != nil {
		return nil, errors.Wrap(err, "unable to encrypt plaintext")
	}

	ct, err = binary.Marshal(&blockchainCiphertext{CT: ct, Hsent: u.hsnd, Ack: ack})
	if err != nil {
		return nil, errors.Wrap(err, "unable to marshal ciphertext")
	}

	u.arec = 0
	u.hsnd = primitives.Digest(sha256.New(), u.hk, u.hsnd, ad, ct)
	u.asnd = append(u.asnd, u.hsnd)

	return ct, nil
}

// Receive invokes the blockchain-ARCAD receive routine.
func (b BlockchainARCAD) Receive(user Uuser, ad, ct []byte) ([]byte, error) {
	var cipher blockchainCiphertext
	if err := binary.Unmarshal(ct, &cipher); err != nil {
		return nil, errors.Wrap(err, "unable to unmarshal ciphertext")
	}

	u := user.(*BlockchainUser)

	oka := bytes.Equal(cipher.Hsent, u.hrec)
	okb := len(cipher.Ack) == 0
	for _, a := range u.asnd {
		okb = okb || bytes.Equal(cipher.Ack, a)
	}
	if !(oka && okb) {
		return nil, errors.New("user are out-of-sync")
	}

	ba, err := binary.Marshal(&blockchainAssociated{AD: ad, Hsent: cipher.Hsent, Ack: cipher.Ack})
	if err != nil {
		return nil, errors.Wrap(err, "unable to marshal associated data")
	}

	msg, err := b.arcad.Receive(u.st, ba, cipher.CT)
	if err != nil {
		return nil, errors.Wrap(err, "unable to decrypt ciphertext")
	}

	u.hrec = primitives.Digest(sha256.New(), u.hk, u.hrec, ad, ct)
	u.arec++

	i := 0
	for len(cipher.Ack) > 0 && i < len(u.asnd) && !bytes.Equal(cipher.Ack, u.asnd[i]) {
		i++
	}
	u.asnd = u.asnd[:i]

	return msg, nil
}
