// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package r1

import (
	"hash"
	"io"

	"github.com/dchest/wots"
)

type lamportOTS struct {
	scheme *wots.Scheme
}

func NewLamportOTS(rand io.Reader, hash func() hash.Hash) *lamportOTS {
	return &lamportOTS{scheme: wots.NewScheme(hash, rand)}
}

func (l *lamportOTS) GenerateKeys() (pk, sk []byte) {
	sk, pk, _ = l.scheme.GenerateKeyPair()
	return
}

func (l *lamportOTS) Sign(sk, message []byte) (signature []byte) {
	signature, _ = l.scheme.Sign(sk, message)
	return
}

func (l *lamportOTS) Verify(pk, message, signature []byte) bool {
	return l.scheme.Verify(pk, message, signature)
}
