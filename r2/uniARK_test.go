package r2

import (
	"bytes"
	"crypto/elliptic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUNIARK(t *testing.T) {
	c := elliptic.P384()

	ecies := NewECIES(c)
	ecdsa := NewECDSA(c)
	sc := NewSigncryption(ecies, ecdsa)

	uni := NewUNIARK(sc)

	s, r, err := uni.Init()
	require.Nil(t, err)

	for i := 0; i < 100; i++ {
		ss, ka, ct, err := uni.Send(s)
		require.Nil(t, err)

		ss, ka1, ct1, err := uni.Send(ss)
		require.Nil(t, err)

		rr, kb, err := uni.Receive(r, ct)
		require.Nil(t, err)
		require.True(t, bytes.Equal(ka, kb))

		rr, kb1, err := uni.Receive(rr, ct1)
		require.Nil(t, err)
		require.True(t, bytes.Equal(ka1, kb1))

		s, r = ss, rr
	}
}
