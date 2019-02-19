// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package dv

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/qantik/ratcheted/primitives/encryption"
)

var (
	//curve = elliptic.P256()
	//ecies = encryption.NewECIES(curve)
	//ecdsa = signature.NewECDSA(curve)
	aes = encryption.NewAES()
	//gcm = encryption.NewGCM()

	arcad = NewARCAD(ecdsa, ecies, aes)
	//arcad = NewLiteARCAD(gcm, aes)
)

func TestARCAD_Alternating(t *testing.T) {
	require := require.New(t)

	msg := []byte("arcad")
	ad := []byte("ad")

	alice, bob, err := arcad.Init()
	require.Nil(err)

	for i := 0; i < 10; i++ {
		ct, err := arcad.Send(alice, ad, msg)
		require.Nil(err)

		pt, err := arcad.Receive(bob, ad, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))

		ct, err = arcad.Send(bob, ad, pt)
		require.Nil(err)

		pt, err = arcad.Receive(alice, ad, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}
}

func TestARCAD_Unidirectional(t *testing.T) {
	require := require.New(t)

	msg := []byte("arcad")
	ad := []byte("ad")

	alice, bob, err := arcad.Init()
	require.Nil(err)

	for i := 0; i < 15; i++ {
		ct, err := arcad.Send(alice, ad, msg)
		require.Nil(err)

		pt, err := arcad.Receive(bob, ad, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}

	for i := 0; i < 15; i++ {
		ct, err := arcad.Send(bob, ad, msg)
		require.Nil(err)

		pt, err := arcad.Receive(alice, ad, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}
}

func TestARCAD_DefUnidirectional(t *testing.T) {
	require := require.New(t)

	msg := []byte("arcad")
	ad := []byte("ad")

	alice, bob, err := arcad.Init()
	require.Nil(err)

	var cts [10][]byte
	for i := 0; i < 10; i++ {
		ct, err := arcad.Send(alice, ad, msg)
		require.Nil(err)

		cts[i] = ct
	}

	for i := 0; i < 10; i++ {
		ct, err := arcad.Send(bob, ad, msg)
		require.Nil(err)

		pt, err := arcad.Receive(alice, ad, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}

	for i := 0; i < 10; i++ {
		pt, err := arcad.Receive(bob, ad, cts[i])
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}
}
