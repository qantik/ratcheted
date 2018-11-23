// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package dratch

import (
	"crypto/rand"
	"crypto/sha256"
	"io"

	"github.com/pkg/errors"

	"golang.org/x/crypto/hkdf"
)

const ppStateSize = 16

// prfPRNG implements the PRF-PRNG scheme based on HDFK with SHA256.
type prfPRNG struct{}

// generate creates a fresh PRF-PRNG state.
func (p prfPRNG) generate() ([]byte, error) {
	state := make([]byte, 16)
	if _, err := rand.Read(state); err != nil {
		return nil, errors.Wrap(err, "unable to generate prf-prng state")
	}
	return state, nil
}

// up returns new PRF-PRNG state and n random bytes.
func (p prfPRNG) up(n int, key, salt []byte) (upd, r []byte, err error) {
	hkdf := hkdf.New(sha256.New, key, salt, nil)

	upd = make([]byte, ppStateSize)
	if _, err := io.ReadFull(hkdf, upd); err != nil {
		return nil, nil, errors.Wrap(err, "unable to poll hkdf")
	}
	r = make([]byte, n)
	if _, err := io.ReadFull(hkdf, r); err != nil {
		return nil, nil, errors.Wrap(err, "unable to poll hkdf")
	}
	return upd, r, nil
}
