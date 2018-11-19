// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package secmsg

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/qantik/ratcheted/primitives/encryption"
	"github.com/qantik/ratcheted/primitives/signature"
)

func TestSecMsg(t *testing.T) {
	require := require.New(t)

	hku := &hkuPKE{pke: encryption.NewECIES(elliptic.P256()), sku: &skuPKE{elliptic.P256()}}
	lamport := signature.NewLamport(rand.Reader, sha256.New)
	kus := &kuSig{lamport}

	sec := &SecMsg{hku: hku, kus: kus, sig: lamport}

	msg := []byte("secmsg")

	alice, bob, err := sec.Init()
	require.Nil(err)

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

	var cts [1000][]byte
	for i := 0; i < 1000/2; i++ {
		ct, err := sec.Send(alice, msg)
		require.Nil(err)
		cts[i] = ct
	}

	for i := 0; i < 1000/2; i++ {
		ct, err := sec.Send(bob, msg)
		require.Nil(err)

		pt, err := sec.Receive(alice, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}

	for i := 0; i < 1000/2; i++ {
		pt, err := sec.Receive(bob, cts[i])
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}
}
