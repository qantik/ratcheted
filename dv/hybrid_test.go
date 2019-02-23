// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package dv

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

var hybrid = NewHybridARCAD(ecdsa, ecies, aes, gcm)

func TestHybridARCAD_Alternating(t *testing.T) {
	require := require.New(t)

	msg := []byte("arcad")
	ad := []byte("ad")

	alice, bob, err := hybrid.Init()
	require.Nil(err)

	for i := 0; i < 10; i++ {
		flag := false
		if i == 5 {
			flag = true
		}

		ct, err := hybrid.Send(alice, ad, msg, flag)
		require.Nil(err)

		pt, err := hybrid.Receive(bob, ad, ct, flag)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))

		ct, err = hybrid.Send(bob, ad, pt, flag)
		require.Nil(err)

		pt, err = hybrid.Receive(alice, ad, ct, flag)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}
}

func TestHybridARCAD_Unidirectional(t *testing.T) {
	require := require.New(t)

	msg := []byte("arcad")
	ad := []byte("ad")

	alice, bob, err := hybrid.Init()
	require.Nil(err)

	for i := 0; i < 10; i++ {
		ct, err := hybrid.Send(alice, ad, msg, false)
		require.Nil(err)

		pt, err := hybrid.Receive(bob, ad, ct, false)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}

	for i := 0; i < 10; i++ {
		ct, err := hybrid.Send(bob, ad, msg, false)
		require.Nil(err)

		pt, err := hybrid.Receive(alice, ad, ct, false)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}
}

func TestHybridARCAD_DefUnidirectional(t *testing.T) {
	require := require.New(t)

	msg := []byte("arcad")
	ad := []byte("ad")

	alice, bob, err := hybrid.Init()
	require.Nil(err)

	var cts [10][]byte
	for i := 0; i < 10; i++ {
		ct, err := hybrid.Send(alice, ad, msg, false)
		require.Nil(err)

		cts[i] = ct
	}

	for i := 0; i < 10; i++ {
		ct, err := hybrid.Send(bob, ad, msg, false)
		require.Nil(err)

		pt, err := hybrid.Receive(alice, ad, ct, false)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}

	for i := 0; i < 10; i++ {
		pt, err := hybrid.Receive(bob, ad, cts[i], false)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}
}
