// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package signature

import (
	"errors"
	"hash"
	"io"

	"github.com/dchest/wots"
)

type Lamport struct {
	scheme *wots.Scheme
}

func NewLamport(rand io.Reader, hash func() hash.Hash) *Lamport {
	return &Lamport{scheme: wots.NewScheme(hash, rand)}
}

func (l Lamport) Generate() (pk, sk []byte, err error) {
	sk, pk, err = l.scheme.GenerateKeyPair()
	return
}

func (l Lamport) Sign(sk, msg []byte) ([]byte, error) {
	return l.scheme.Sign(sk, msg)
}

func (l Lamport) Verify(pk, msg, sig []byte) error {
	if !l.scheme.Verify(pk, msg, sig) {
		return errors.New("unable to verify signature")
	}
	return nil
}
