// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package dratch

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/qantik/ratcheted/primitives/encryption"
)

func TestDRatch(t *testing.T) {
	require := require.New(t)

	dr := NewDRatch(encryption.NewGCM())

	msg := []byte("dratch")

	alice, bob, err := dr.Init()
	require.Nil(err)

	for i := 0; i < 10; i++ {
		ct1, err := dr.Send(alice, msg)
		require.Nil(err)
		ct2, err := dr.Send(alice, msg)
		require.Nil(err)
		ct3, err := dr.Send(alice, msg)
		require.Nil(err)

		pt2, err := dr.Receive(bob, ct2)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt2))

		ct, err := dr.Send(bob, msg)
		require.Nil(err)

		pt, err := dr.Receive(alice, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))

		pt1, err := dr.Receive(bob, ct1)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt1))

		pt3, err := dr.Receive(bob, ct3)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt3))
	}
}
