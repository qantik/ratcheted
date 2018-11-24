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

func TestBARK(t *testing.T) {
	require := require.New(t)
	c := elliptic.P256()

	//ecies := encryption.NewOAEP()
	ecies := encryption.NewECIES(c)
	ecdsa := signature.NewECDSA(c)
	sc := &signcryption{ecies, ecdsa}

	uni := NewUni(sc)
	//uni := NewLiteUni(encryption.NewGCM())

	bark := NewBARK(uni)

	pa, pb, err := bark.Init()
	require.Nil(err)

	for j := 0; j < 100; j++ {
		pau, ka, ct, err := bark.Send(pa)
		require.Nil(err)

		pbu, kb, err := bark.Receive(pb, ct)
		require.Nil(err)
		require.True(bytes.Equal(ka, kb))

		pa, pb = pau, pbu
	}

	for j := 0; j < 100; j++ {
		pbu, ka, ct, err := bark.Send(pb)
		require.Nil(err)

		pau, kb, err := bark.Receive(pa, ct)
		require.Nil(err)
		require.True(bytes.Equal(ka, kb))

		pa, pb = pau, pbu

	}
}
