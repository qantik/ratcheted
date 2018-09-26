package r2

import (
	"bytes"
	"crypto/elliptic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestECIES(t *testing.T) {
	ecies := NewECIES(elliptic.P256())

	sk, pk, err := ecies.GenerateKeys()
	require.Nil(t, err)

	var msg [32]byte
	msg[0] = 1
	msg[1] = 2
	msg[2] = 3
	msg[3] = 4
	msg[4] = 5
	msg[5] = 6

	ct, err := ecies.Encrypt(pk, msg[:])
	require.Nil(t, err)
	pt, err := ecies.Decrypt(sk, ct)
	require.Nil(t, err)

	require.True(t, bytes.Equal(msg[:], pt))
}
