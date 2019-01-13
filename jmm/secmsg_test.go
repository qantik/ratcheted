// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package jmm

import (
	"bytes"
	"crypto/elliptic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/qantik/ratcheted/primitives/encryption"
	"github.com/qantik/ratcheted/primitives/signature"
)

func TestSecMsg(t *testing.T) {
	require := require.New(t)

	curve := elliptic.P256()
	ecdsa := signature.NewECDSA(curve)

	hku := &hkuPKE{pke: encryption.NewECIES(curve), sku: &skuPKE{curve}}
	kus := &kuSig{ecdsa}

	sec := &SecMsg{hku: hku, kus: kus, sig: ecdsa}

	msg := []byte("secmsg")

	alice, bob, err := sec.Init()
	require.Nil(err)

	n := 10

	var cts [1000][]byte
	for i := 0; i < n/2; i++ {
		ct, err := sec.Send(alice, msg)
		require.Nil(err)

		cts[i] = ct
	}

	for i := 0; i < n/2; i++ {
		ct, err := sec.Send(bob, msg)
		require.Nil(err)

		pt, err := sec.Receive(alice, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}

	for i := 0; i < n/2; i++ {
		pt, err := sec.Receive(bob, cts[i])
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}

	//for i := 0; i < 10; i++ {
	//	ct, err := sec.Send(alice, msg)
	//	require.Nil(err)

	//	ct1, err := sec.Send(alice, msg)
	//	require.Nil(err)

	//	pt, err := sec.Receive(bob, ct)
	//	require.Nil(err)
	//	require.True(bytes.Equal(msg, pt))

	//	ct, err = sec.Send(bob, msg)
	//	require.Nil(err)

	//	pt, err = sec.Receive(alice, ct)
	//	require.Nil(err)
	//	require.True(bytes.Equal(msg, pt))

	//	pt, err = sec.Receive(bob, ct1)
	//	require.Nil(err)
	//	require.True(bytes.Equal(msg, pt))
	//}
}
