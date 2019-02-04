package dv

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLiteBARK_Alternating(t *testing.T) {
	require := require.New(t)

	//alice, bob, err := bark.Init()
	alice, bob, err := lBARK.Init()
	require.Nil(err)

	for i := 0; i < 10; i++ {
		ka, ct, err := lBARK.Send(alice)
		require.Nil(err)

		kb, err := lBARK.Receive(bob, ct)
		require.Nil(err)
		require.True(bytes.Equal(ka, kb))

		ka, ct, err = lBARK.Send(bob)
		require.Nil(err)

		kb, err = lBARK.Receive(alice, ct)
		require.Nil(err)
		require.True(bytes.Equal(ka, kb))
	}
}

func TestLiteBARK_Unidirectional(t *testing.T) {
	require := require.New(t)

	alice, bob, err := lBARK.Init()
	require.Nil(err)

	for i := 0; i < 10; i++ {
		ka, ct, err := lBARK.Send(alice)
		require.Nil(err)

		kb, err := lBARK.Receive(bob, ct)
		require.Nil(err)
		require.True(bytes.Equal(ka, kb))
	}

	for i := 0; i < 10; i++ {
		ka, ct, err := lBARK.Send(bob)
		require.Nil(err)

		kb, err := lBARK.Receive(alice, ct)
		require.Nil(err)
		require.True(bytes.Equal(ka, kb))
	}
}

func TestLiteBARK_DefUnidirectional(t *testing.T) {
	require := require.New(t)

	alice, bob, err := lBARK.Init()
	require.Nil(err)

	var ks, cts [10][]byte
	for i := 0; i < 10; i++ {
		ka, ct, err := lBARK.Send(alice)
		require.Nil(err)

		ks[i] = ka
		cts[i] = ct
	}

	for i := 0; i < 10; i++ {
		ka, ct, err := lBARK.Send(bob)
		require.Nil(err)

		kb, err := lBARK.Receive(alice, ct)
		require.Nil(err)
		require.True(bytes.Equal(ka, kb))
	}

	for i := 0; i < 10; i++ {
		kb, err := lBARK.Receive(bob, cts[i])
		require.Nil(err)
		require.True(bytes.Equal(ks[i], kb))
	}
}
