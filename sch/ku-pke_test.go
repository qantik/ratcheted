// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package sch

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/qantik/ratcheted/primitives/hibe"
)

func TestKUPKE(t *testing.T) {
	require := require.New(t)

	k := kuPKE{hibe: hibe.NewGentry()}

	pk, sk, err := k.generate()
	require.Nil(err)

	msg := []byte("ku-PKE")
	delta := []byte("delta")

	for i := 0; i < 10; i++ {
		ct, err := k.encrypt(pk, msg)
		require.Nil(err)

		pt, err := k.decrypt(sk, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))

		pk, err = k.updatePublicKey(pk, delta)
		require.Nil(err)
		sk, err = k.updatePrivateKey(sk, delta)
		require.Nil(err)
	}
}
