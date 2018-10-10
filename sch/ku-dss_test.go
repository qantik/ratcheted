// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package sch

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/qantik/ratcheted/primitives/signature"
)

func TestKUDSS(t *testing.T) {
	require := require.New(t)

	k := &kuDSS{signature: signature.NewBellare()}

	pk, sk, err := k.generate()
	require.Nil(err)

	msg := []byte("kuDSS")
	delta := []byte("delta")

	for i := 0; i < 10; i++ {
		sig, err := k.sign(sk, msg)
		require.Nil(err)
		require.Nil(k.verify(pk, msg, sig))

		pk, err = k.updatePublicKey(pk, delta)
		require.Nil(err)
		sk, err = k.updatePrivateKey(sk, delta)
		require.Nil(err)
	}
}
