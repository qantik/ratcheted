// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package dratch

import (
	"bytes"
	"crypto/elliptic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/qantik/ratcheted/primitives/encryption"
	"github.com/qantik/ratcheted/primitives/signature"
)

func TestDRatch(t *testing.T) {
	require := require.New(t)

	dr := NewDRatch(encryption.NewGCM(), nil, nil)

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

func TestDRatchPK(t *testing.T) {
	require := require.New(t)

	curve := elliptic.P256()
	dr := NewDRatch(encryption.NewGCM(), encryption.NewECIES(curve), signature.NewECDSA(curve))

	msg := []byte("dratch")

	alice, bob, err := dr.Init()
	require.Nil(err)

	for i := 0; i < 10; i++ {
		ct, err := dr.Send(alice, msg)
		require.Nil(err)
		ct2, err := dr.Send(alice, msg)
		require.Nil(err)

		pt, err := dr.Receive(bob, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))

		pt, err = dr.Receive(bob, ct2)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))

		ct3, err := dr.Send(bob, msg)
		require.Nil(err)
		ct4, err := dr.Send(bob, msg)
		require.Nil(err)

		pt, err = dr.Receive(alice, ct3)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))

		pt, err = dr.Receive(alice, ct4)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))

	}
}
