// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package bark

import (
	"bytes"
	"testing"

	"github.com/qantik/ratcheted/primitives/encryption"
	"github.com/stretchr/testify/require"
)

func TestBARK(t *testing.T) {
	require := require.New(t)

	//uni := NewUni(&signcryption{ecies, ecdsa})
	uni := NewLiteUni(encryption.NewGCM())
	bark := NewBARK(uni)

	alice, bob, err := bark.Init()
	require.Nil(err)

	for i := 0; i < 10; i++ {
		ka, ct, err := bark.Send(alice)
		require.Nil(err)

		kb, err := bark.Receive(bob, ct)
		require.Nil(err)
		require.True(bytes.Equal(ka, kb))

		ka, ct, err = bark.Send(bob)
		require.Nil(err)

		kb, err = bark.Receive(alice, ct)
		require.Nil(err)
		require.True(bytes.Equal(ka, kb))
	}
}
