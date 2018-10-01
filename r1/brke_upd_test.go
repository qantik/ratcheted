package r1

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/qantik/ratcheted/hibe"
	"github.com/stretchr/testify/require"
)

func TestUpd(t *testing.T) {
	require := require.New(t)

	upd := NewUpd(hibe.NewGentry(), NewLamportOTS(rand.Reader, sha256.New))

	ad := []byte{1, 2, 3}

	a, b, err := upd.Init()
	require.Nil(err)

	for i := 0; i < 10; i++ {
		ka, c, err := upd.Send(a, ad)
		require.Nil(err)

		ka1, c1, err := upd.Send(a, ad)
		require.Nil(err)

		ka2, c2, err := upd.Send(b, ad)
		require.Nil(err)

		kb2, err := upd.Receive(a, ad, c2)
		require.Nil(err)
		require.True(bytes.Equal(ka2, kb2))

		kb, err := upd.Receive(b, ad, c)
		require.Nil(err)
		require.True(bytes.Equal(ka, kb))

		kb1, err := upd.Receive(b, ad, c1)
		require.Nil(err)
		require.True(bytes.Equal(ka1, kb1))

	}
}
