package r2

import (
	"crypto/elliptic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestECDSA(t *testing.T) {
	c := elliptic.P256()

	e := NewECDSA(c)

	sk, pk, err := e.GenerateKeys()
	require.Nil(t, err)

	msg := []byte("hello")

	sig, err := e.Sign(sk, msg)
	require.Nil(t, err)

	require.Nil(t, e.Verify(pk, msg, sig))
}
