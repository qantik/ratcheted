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

	alice, bob, err := hybrid.Init()
	require.Nil(err)

	for i := 0; i < 10; i++ {
		ad := []byte("ad")
		if i&5 == 0 {
			ad = append([]byte{byte(1)}, ad...)
		} else {
			ad = append([]byte{byte(0)}, ad...)
		}

		ct, err := hybrid.Send(alice, ad, msg)
		require.Nil(err)

		pt, err := hybrid.Receive(bob, ad, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))

		ct, err = hybrid.Send(bob, ad, pt)
		require.Nil(err)

		pt, err = hybrid.Receive(alice, ad, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}
}

func TestHybridARCAD_Unidirectional(t *testing.T) {
	require := require.New(t)

	msg := []byte("arcad")
	ad := []byte("\x00ad")

	alice, bob, err := hybrid.Init()
	require.Nil(err)

	for i := 0; i < 10; i++ {
		ct, err := hybrid.Send(alice, ad, msg)
		require.Nil(err)

		pt, err := hybrid.Receive(bob, ad, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}

	for i := 0; i < 10; i++ {
		ct, err := hybrid.Send(bob, ad, msg)
		require.Nil(err)

		pt, err := hybrid.Receive(alice, ad, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}
}

func TestHybridARCAD_DefUnidirectional(t *testing.T) {
	require := require.New(t)

	msg := []byte("arcad")
	ad := []byte("\x00ad")

	alice, bob, err := hybrid.Init()
	require.Nil(err)

	var cts [10][]byte
	for i := 0; i < 10; i++ {
		ct, err := hybrid.Send(alice, ad, msg)
		require.Nil(err)

		cts[i] = ct
	}

	for i := 0; i < 10; i++ {
		ct, err := hybrid.Send(bob, ad, msg)
		require.Nil(err)

		pt, err := hybrid.Receive(alice, ad, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}

	for i := 0; i < 10; i++ {
		pt, err := hybrid.Receive(bob, ad, cts[i])
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}
}
