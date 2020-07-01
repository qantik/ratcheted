// (c) 2020 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package dv

import (
	"crypto/rand"
	"crypto/sha256"

	"github.com/pkg/errors"

	"github.com/qantik/ratcheted/primitives"
	"github.com/qantik/ratcheted/primitives/encryption"
)

type SARCAD struct {
	otae encryption.Authenticated
}

type SARCADUser struct {
	hk     []byte
	sk, rk []byte
}

func NewSARCAD(otae encryption.Authenticated) *SARCAD {
	return &SARCAD{otae: otae}
}

func (s SARCAD) Init() (alice, bob User, err error) {
	hk := make([]byte, hashKeySize)
	if _, err := rand.Read(hk); err != nil {
		return nil, nil, errors.Wrap(err, "unable to initialize sarcad protocol")
	}

	k1, k2 := make([]byte, 32), make([]byte, 32)
	if _, err := rand.Read(k1); err != nil {
		return nil, nil, errors.Wrap(err, "unable to initialize sarcad protocol")
	}
	if _, err := rand.Read(k2); err != nil {
		return nil, nil, errors.Wrap(err, "unable to initialize sarcad protocol")
	}

	alice = &SARCADUser{hk: hk, sk: k1, rk: k2}
	bob = &SARCADUser{hk: hk, sk: k2, rk: k1}
	return
}

func (s SARCAD) Send(user User, ad, msg []byte) ([]byte, error) {
	u := user.(*SARCADUser)

	ct, err := s.otae.Encrypt(u.sk, msg, ad)
	if err != nil {
		return nil, errors.Wrap(err, "unable to encrypt plaintext")
	}

	u.sk = primitives.Digest(sha256.New(), u.hk, u.sk)

	return ct, nil
}

func (s SARCAD) Receive(user User, ad, ct []byte) ([]byte, error) {
	u := user.(*SARCADUser)

	pt, err := s.otae.Decrypt(u.rk, ct, ad)
	if err != nil {
		return nil, errors.Wrap(err, "unable to decrypt ciphertext")
	}

	u.rk = primitives.Digest(sha256.New(), u.hk, u.rk)

	return pt, nil
}

// Size returns the size of a user state in bytes.
func (b SARCADUser) Size() int {
	return 16 + 32 + 32
}
