package r2

import (
	"bytes"
	"crypto/elliptic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLa(t *testing.T) {
	c := elliptic.P256()

	ecies := NewECIES(c)
	ecdsa := NewECDSA(c)
	sc := NewSigncryption(ecies, ecdsa)

	sks, skr, err := sc.GenerateSignKeys()
	require.Nil(t, err)
	pks, pkr, err := sc.GenerateCipherKeys()
	require.Nil(t, err)

	msg := make([]byte, 3)
	msg[0] = 1
	msg[1] = 2
	msg[2] = 3

	ad := []byte{100, 200}

	ct, err := sc.Signcrypt(sks, pkr, ad, msg)
	require.Nil(t, err)

	pt, err := sc.Unsigncrypt(skr, pks, ad, ct)
	require.Nil(t, err)
	require.True(t, bytes.Equal(msg, pt))
}
