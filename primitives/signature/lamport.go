// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package signature

import (
	"errors"
	"hash"
	"io"

	"github.com/dchest/wots"
)

// Lamport is the Lamport one-time signature handler object.
type Lamport struct {
	scheme *wots.Scheme
}

// NewLamport creates a fresh Lamport instance for a given hash function.
func NewLamport(rand io.Reader, hash func() hash.Hash) *Lamport {
	return &Lamport{scheme: wots.NewScheme(hash, rand)}
}

// Generate creates a new public/secret key pair.
func (l Lamport) Generate() (pk, sk []byte, err error) {
	sk, pk, err = l.scheme.GenerateKeyPair()
	return
}

// Sign creates a signature of a given message using a secret key.
func (l Lamport) Sign(sk, msg []byte) ([]byte, error) {
	return l.scheme.Sign(sk, msg)
}

// Verify checks the validity of signature using a public key.
func (l Lamport) Verify(pk, msg, sig []byte) error {
	if !l.scheme.Verify(pk, msg, sig) {
		return errors.New("unable to verify signature")
	}
	return nil
}
