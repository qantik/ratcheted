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

	pa, pb, err := bark.Init()
	require.Nil(err)

	for i := 0; i < 10; i++ {

		pau, ka, ct, err := bark.Send(pa)
		require.Nil(err)

		pbu, kb, err := bark.Receive(pb, ct)
		require.Nil(err)
		require.True(bytes.Equal(ka, kb))

		pbu, ka, ct, err = bark.Send(pbu)
		require.Nil(err)

		pau, kb, err = bark.Receive(pau, ct)
		require.Nil(err)
		require.True(bytes.Equal(ka, kb))

		pa, pb = pau, pbu
	}
}
