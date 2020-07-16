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
	aes  encryption.Symmetric

	oteae bool
}

type SARCADUser struct {
	hk     []byte
	sk, rk []byte
}

func NewSARCAD(otae encryption.Authenticated, aes encryption.Symmetric, oteae bool) *SARCAD {
	return &SARCAD{otae: otae, aes: aes, oteae: oteae}
}

func (s SARCAD) Init() (alice, bob User, err error) {
	var hk []byte
	if !s.oteae {
		hk = make([]byte, hashKeySize)
		if _, err := rand.Read(hk); err != nil {
			return nil, nil, errors.Wrap(err, "unable to initialize sarcad protocol")
		}
	}

	k1, k2 := make([]byte, 16), make([]byte, 16)
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

	if s.oteae {
		ones := []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
		enc, _ := s.aes.Encrypt(u.sk, ones)
		u.sk = enc[16:]
	} else {
		dig := primitives.Digest(sha256.New(), u.hk, u.sk)
		u.sk = dig[:16]
	}

	return ct, nil
}

func (s SARCAD) Receive(user User, ad, ct []byte) ([]byte, error) {
	u := user.(*SARCADUser)

	pt, err := s.otae.Decrypt(u.rk, ct, ad)
	if err != nil {
		return nil, errors.Wrap(err, "unable to decrypt ciphertext")
	}

	if s.oteae {
		ones := []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
		enc, _ := s.aes.Encrypt(u.rk, ones)
		u.rk = enc[16:]
	} else {
		dig := primitives.Digest(sha256.New(), u.hk, u.rk)
		u.rk = dig[:16]
	}

	return pt, nil
}

// Size returns the size of a user state in bytes.
func (b SARCADUser) Size() int {
	return len(b.hk) + len(b.sk) + len(b.rk)
}
