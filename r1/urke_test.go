package r1

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

//func TestURKE(t *testing.T) {
//	require := require.New(t)
//
//	snd, rcv := urkeInit()
//
//	ad := []byte{1, 2, 3}
//
//	for i := 0; i < 100; i++ {
//		ka, C := snd.send(ad)
//		kb := rcv.receive(ad, C)
//		require.Equal(0, bytes.Compare(ka, kb))
//	}
//}

func TestURKE(t *testing.T) {
	require := require.New(t)

	gentry := NewGentryKEM(rand.Reader)
	urke := NewURKE(gentry)

	s, r := urke.init()
	ad := []byte{1, 2, 3}

	for i := 0; i < 10; i++ {
		ka, tau, C := urke.send(s, ad)
		kb := urke.receive(r, ad, tau, C)
		require.True(bytes.Equal(ka, kb))
	}
}
