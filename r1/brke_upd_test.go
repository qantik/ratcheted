package r1

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/qantik/ratcheted/hibe"
)

var brke = NewUpd(hibe.NewGentry(), NewLamportOTS(rand.Reader, sha256.New))

func TestBRKE_Synchronous(t *testing.T) {
	require := require.New(t)

	ad := []byte{1, 2, 3}

	a, b, err := brke.Init()
	require.Nil(err)

	for i := 0; i < 10; i++ {
		ka, c, err := brke.Send(a, ad)
		require.Nil(err)

		kb, err := brke.Receive(b, ad, c)
		require.Nil(err)
		require.True(bytes.Equal(ka, kb))

		kb, c, err = brke.Send(b, ad)
		require.Nil(err)

		ka, err = brke.Receive(a, ad, c)
		require.Nil(err)
		require.True(bytes.Equal(ka, kb))
	}
}

func TestBRKE_Aynchronous(t *testing.T) {
	require := require.New(t)

	ad := []byte{1, 2, 3}

	a, b, err := brke.Init()
	require.Nil(err)

	for i := 0; i < 10; i++ {
		ka1, c1, err := brke.Send(a, ad)
		require.Nil(err)

		kb2, c2, err := brke.Send(b, ad)
		require.Nil(err)

		kb1, err := brke.Receive(b, ad, c1)
		require.Nil(err)
		require.True(bytes.Equal(ka1, kb1))

		ka2, err := brke.Receive(a, ad, c2)
		require.Nil(err)
		require.True(bytes.Equal(ka2, kb2))
	}
}
