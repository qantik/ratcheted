package signature

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLamport(t *testing.T) {
	require := require.New(t)

	lamport := NewLamport(rand.Reader, sha256.New)

	pk, sk, err := lamport.Generate()
	require.Nil(err)

	msg := []byte("lamport")

	sig, err := lamport.Sign(sk, msg)
	require.Nil(err)

	require.Nil(lamport.Verify(pk, msg, sig))
	require.NotNil(lamport.Verify(pk, []byte("abc"), sig))
}
