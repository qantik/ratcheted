// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package bark

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

	bark     = NewBARK(&uniARCAD{&signcryption{ecies, ecdsa}})
	liteBARK = NewBARK(NewLiteUniARCAD(gcm))
)

func TestBARK_Alternating(t *testing.T) {
	require := require.New(t)

	alice, bob, err := bark.Init()
	//alice, bob, err := liteBARK.Init()
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

func TestBARK_Unidirectional(t *testing.T) {
	require := require.New(t)

	alice, bob, err := bark.Init()
	require.Nil(err)

	for i := 0; i < 10; i++ {
		ka, ct, err := bark.Send(alice)
		require.Nil(err)

		kb, err := bark.Receive(bob, ct)
		require.Nil(err)
		require.True(bytes.Equal(ka, kb))
	}

	for i := 0; i < 10; i++ {
		ka, ct, err := bark.Send(bob)
		require.Nil(err)

		kb, err := bark.Receive(alice, ct)
		require.Nil(err)
		require.True(bytes.Equal(ka, kb))
	}
}

func TestBARK_DefUnidirectional(t *testing.T) {
	require := require.New(t)

	alice, bob, err := bark.Init()
	require.Nil(err)

	var ks, cts [10][]byte
	for i := 0; i < 10; i++ {
		ka, ct, err := bark.Send(alice)
		require.Nil(err)

		ks[i] = ka
		cts[i] = ct
	}

	for i := 0; i < 10; i++ {
		ka, ct, err := bark.Send(bob)
		require.Nil(err)

		kb, err := bark.Receive(alice, ct)
		require.Nil(err)
		require.True(bytes.Equal(ka, kb))
	}

	for i := 0; i < 10; i++ {
		kb, err := bark.Receive(bob, cts[i])
		require.Nil(err)
		require.True(bytes.Equal(ks[i], kb))
	}
}
