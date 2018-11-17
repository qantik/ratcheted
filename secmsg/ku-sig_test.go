// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package secmsg

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/qantik/ratcheted/primitives/signature"
)

func TestKuSig(t *testing.T) {
	require := require.New(t)

	lamport := signature.NewLamport(rand.Reader, sha256.New)

	ks := &kuSig{signature: lamport}

	msg := []byte("ku-sig")

	pk, sk, err := ks.generate()
	require.Nil(err)

	_, bdl, err := ks.sign(sk, msg)
	require.Nil(err)

	_, err = ks.verify(pk, msg, bdl)
	require.Nil(err)
}
