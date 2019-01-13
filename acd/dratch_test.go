// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package acd

import (
	"bytes"
	"crypto/elliptic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/qantik/ratcheted/primitives/encryption"
	"github.com/qantik/ratcheted/primitives/signature"
)

var (
	curve = elliptic.P256()
	ecies = encryption.NewECIES(curve)
	ecdsa = signature.NewECDSA(curve)
	gcm   = encryption.NewGCM()

	dr   = NewDRatch(gcm, nil, nil)
	drpk = NewDRatch(gcm, ecies, ecdsa)

	msg = []byte{
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
	}
)

func Test_Alternating(t *testing.T) {
	require := require.New(t)

	alice, bob, err := dr.Init()
	require.Nil(err)

	for i := 0; i < 10; i++ {
		ct, err := dr.Send(alice, msg)
		require.Nil(err)

		pt, err := dr.Receive(bob, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))

		ct, err = dr.Send(bob, msg)
		require.Nil(err)

		pt, err = dr.Receive(alice, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}
}

func Test_Unidirectional(t *testing.T) {
	require := require.New(t)

	alice, bob, err := dr.Init()
	require.Nil(err)

	for i := 0; i < 10; i++ {
		ct, err := dr.Send(alice, msg)
		require.Nil(err)

		pt, err := dr.Receive(bob, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}

	for i := 0; i < 10; i++ {
		ct, err := dr.Send(bob, msg)
		require.Nil(err)

		pt, err := dr.Receive(alice, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}
}

func Test_DefUnidirectional(t *testing.T) {
	require := require.New(t)

	alice, bob, err := dr.Init()
	require.Nil(err)

	var cts [10][]byte
	for i := 0; i < 10; i++ {
		ct, err := dr.Send(alice, msg)
		require.Nil(err)

		cts[i] = ct
	}

	for i := 0; i < 10; i++ {
		ct, err := dr.Send(bob, msg)
		require.Nil(err)

		pt, err := dr.Receive(alice, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}

	for i := 0; i < 10; i++ {
		pt, err := dr.Receive(bob, cts[i])
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}
}
