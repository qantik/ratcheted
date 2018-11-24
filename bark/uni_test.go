// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package bark

import (
	"bytes"
	"crypto/elliptic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/qantik/ratcheted/primitives/encryption"
	"github.com/qantik/ratcheted/primitives/signature"
)

func TestUniBARK(t *testing.T) {
	c := elliptic.P256()

	ecies := encryption.NewECIES(c)
	ecdsa := signature.NewECDSA(c)
	sc := &signcryption{ecies, ecdsa}

	uni := NewUni(sc)

	s, r, err := uni.Init()
	require.Nil(t, err)

	pt := []byte("uni-bark")
	ad := []byte("associated-data")

	for i := 0; i < 15; i++ {
		ss, ct1, err := uni.Send(s, ad, pt, false)
		require.Nil(t, err)

		ss, ct2, err := uni.Send(ss, ad, pt, false)
		require.Nil(t, err)

		rr, msg, err := uni.Receive(r, ad, ct1)
		require.Nil(t, err)
		require.True(t, bytes.Equal(pt, msg))

		rr, msg, err = uni.Receive(rr, ad, ct2)
		require.Nil(t, err)
		require.True(t, bytes.Equal(pt, msg))

		s, r = ss, rr
	}
}
