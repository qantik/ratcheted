// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package brke

import (
	"bytes"
	"crypto/elliptic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/qantik/ratcheted/primitives/hibe"
	"github.com/qantik/ratcheted/primitives/signature"
)

var (
	curve  = elliptic.P256()
	ecdsa  = signature.NewECDSA(curve)
	gentry = hibe.NewGentry()

	brke = NewBRKE(gentry, ecdsa)

	ad = []byte{
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

func TestBRKE_Alternating(t *testing.T) {
	require := require.New(t)

	brke := NewBRKE(hibe.NewGentry(), signature.NewECDSA(curve))

	alice, bob, err := brke.Init()
	require.Nil(err)

	for i := 0; i < 5; i++ {
		ka, c, err := brke.Send(alice, ad)
		require.Nil(err)

		kb, err := brke.Receive(bob, ad, c)
		require.Nil(err)
		require.True(bytes.Equal(ka, kb))

		kb, c, err = brke.Send(bob, ad)
		require.Nil(err)

		ka, err = brke.Receive(alice, ad, c)
		require.Nil(err)
		require.True(bytes.Equal(ka, kb))
	}
}

func TestBRKE_Unidirectional(t *testing.T) {
	require := require.New(t)

	brke := NewBRKE(hibe.NewGentry(), signature.NewECDSA(curve))

	alice, bob, err := brke.Init()
	require.Nil(err)

	for i := 0; i < 5; i++ {
		ka, c, err := brke.Send(alice, ad)
		require.Nil(err)

		kb, err := brke.Receive(bob, ad, c)
		require.Nil(err)
		require.True(bytes.Equal(ka, kb))
	}

	for i := 0; i < 5; i++ {
		kb, c, err := brke.Send(bob, ad)
		require.Nil(err)

		ka, err := brke.Receive(alice, ad, c)
		require.Nil(err)
		require.True(bytes.Equal(ka, kb))
	}
}

func TestBRKE_DefUnidirectional(t *testing.T) {
	require := require.New(t)

	brke := NewBRKE(hibe.NewGentry(), signature.NewECDSA(curve))

	alice, bob, err := brke.Init()
	require.Nil(err)

	var ks [5][]byte
	var cs [5][][]byte
	for i := 0; i < 5; i++ {
		k, c, err := brke.Send(alice, ad)
		require.Nil(err)

		ks[i] = k
		cs[i] = c
	}

	for i := 0; i < 5; i++ {
		kb, c, err := brke.Send(bob, ad)
		require.Nil(err)

		ka, err := brke.Receive(alice, ad, c)
		require.Nil(err)
		require.True(bytes.Equal(ka, kb))
	}

	for i := 0; i < 5; i++ {
		k, err := brke.Receive(bob, ad, cs[i])
		require.Nil(err)
		require.True(bytes.Equal(ks[i], k))
	}
}
