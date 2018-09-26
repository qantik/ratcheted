package r2

import (
	"bytes"
	"crypto/elliptic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUNIARK(t *testing.T) {
	c := elliptic.P256()

	ecies := NewECIES(c)
	ecdsa := NewECDSA(c)
	sc := NewSigncryption(ecies, ecdsa)

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
