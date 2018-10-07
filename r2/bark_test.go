package r2

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBARK(t *testing.T) {
	//c := elliptic.P256()

	//ecies := NewECIES(c)
	//ecdsa := NewECDSA(c)
	//sc := NewSigncryption(ecies, ecdsa)

	//uni := NewUNIARK(sc)
	uni := NewLiteUniARCAD()

	bark := NewBARK(uni)

	pa, pb, err := bark.Init()
	require.Nil(t, err)

	for i := 0; i < 500; i++ {
		pau, ka, ct, err := bark.Send(pa)
		require.Nil(t, err)

		pbu, kb, err := bark.Receive(pb, ct)
		require.Nil(t, err)
		require.True(t, bytes.Equal(ka, kb))

		pbu, ka, ct, err = bark.Send(pbu)
		require.Nil(t, err)

		pau, kb, err = bark.Receive(pau, ct)
		require.Nil(t, err)
		require.True(t, bytes.Equal(ka, kb))

		pa, pb = pau, pbu
	}

	//_, ka, ct, err = bark.Send(pau)
	//require.Nil(t, err)
	//_, kb, err = bark.Receive(pbu, ct)
	//require.Nil(t, err)
	//require.True(t, bytes.Equal(ka, kb))

}

func TestBARK1(t *testing.T) {
	//c := elliptic.P256()

	//ecies := NewECIES(c)
	//ecdsa := NewECDSA(c)
	//sc := NewSigncryption(ecies, ecdsa)

	//uni := NewUNIARK(sc)
	uni := NewLiteUniARCAD()

	bark := NewBARK(uni)

	pa, pb, err := bark.Init()
	require.Nil(t, err)

	for i := 0; i < 500; i++ {
		pau, ka, ct, err := bark.Send(pa)
		require.Nil(t, err)

		pbu, kb, err := bark.Receive(pb, ct)
		require.Nil(t, err)
		require.True(t, bytes.Equal(ka, kb))

		//pbu, ka, ct, err = bark.Send(pbu)
		//require.Nil(t, err)

		//pau, kb, err = bark.Receive(pau, ct)
		//require.Nil(t, err)
		//require.True(t, bytes.Equal(ka, kb))

		pa, pb = pau, pbu
	}

	//_, ka, ct, err = bark.Send(pau)
	//require.Nil(t, err)
	//_, kb, err = bark.Receive(pbu, ct)
	//require.Nil(t, err)
	//require.True(t, bytes.Equal(ka, kb))

}
