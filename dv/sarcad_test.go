// (c) 2020 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package dv

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/qantik/ratcheted/primitives/encryption"
)

var sarcad = NewSARCAD(encryption.NewGCM())

func TestSARCAD_Alternating(t *testing.T) {
	require := require.New(t)

	msg := []byte("sarcad")
	ad := []byte("ad")

	alice, bob, err := sarcad.Init()
	require.Nil(err)

	for i := 0; i < 10; i++ {
		ct, err := sarcad.Send(alice, ad, msg)
		require.Nil(err)

		pt, err := sarcad.Receive(bob, ad, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))

		ct, err = sarcad.Send(bob, ad, pt)
		require.Nil(err)

		pt, err = sarcad.Receive(alice, ad, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}
}

func TestSARCAD_Unidirectional(t *testing.T) {
	require := require.New(t)

	msg := []byte("arcad")
	ad := []byte("ad")

	alice, bob, err := sarcad.Init()
	require.Nil(err)

	for i := 0; i < 10; i++ {
		ct, err := sarcad.Send(alice, ad, msg)
		require.Nil(err)

		pt, err := sarcad.Receive(bob, ad, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}

	for i := 0; i < 10; i++ {
		ct, err := sarcad.Send(bob, ad, msg)
		require.Nil(err)

		pt, err := sarcad.Receive(alice, ad, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}
}

func TestSARCAD_DefUnidirectional(t *testing.T) {
	require := require.New(t)

	msg := []byte("arcad")
	ad := []byte("ad")

	alice, bob, err := sarcad.Init()
	require.Nil(err)

	var cts [10][]byte
	for i := 0; i < 10; i++ {
		ct, err := sarcad.Send(alice, ad, msg)
		require.Nil(err)

		cts[i] = ct
	}

	for i := 0; i < 10; i++ {
		ct, err := sarcad.Send(bob, ad, msg)
		require.Nil(err)

		pt, err := sarcad.Receive(alice, ad, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}

	for i := 0; i < 10; i++ {
		pt, err := sarcad.Receive(bob, ad, cts[i])
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}
}
