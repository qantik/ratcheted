// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package r2

import (
	"bytes"
	"crypto/elliptic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/qantik/ratcheted/primitives/encryption"
	"github.com/qantik/ratcheted/primitives/signature"
)

func TestUNIARK(t *testing.T) {
	c := elliptic.P256()

	ecies := encryption.NewECIES(c)
	ecdsa := signature.NewECDSA(c)
	sc := &signcryption{ecies, ecdsa}

	uni := NewUNIARK(sc)

	s, r, err := uni.Init()
	require.Nil(t, err)

	pt := []byte{1, 2, 3}
	ad := []byte{100, 200}

	for i := 0; i < 15; i++ {
		ss, ct, err := uni.Send(s, ad, pt)
		require.Nil(t, err)

		ss, ct1, err := uni.Send(ss, ad, pt)
		require.Nil(t, err)

		rr, pt1, err := uni.Receive(r, ad, ct)
		require.Nil(t, err)
		require.True(t, bytes.Equal(pt, pt1))

		rr, pt1, err = uni.Receive(rr, ad, ct1)
		require.Nil(t, err)
		require.True(t, bytes.Equal(pt, pt1))

		s, r = ss, rr
	}
}
