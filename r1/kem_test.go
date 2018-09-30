package r1

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/qantik/ratcheted/hibe"
)

func TestKEM(t *testing.T) {
	require := require.New(t)

	kem := &kem{hibe.NewGentry()}

	var seed [128]byte
	rand.Read(seed[:])

	pk, sk, err := kem.Generate(seed[:])
	require.Nil(err)

	ka, c, err := kem.Encrypt(pk)
	require.Nil(err)

	kb, err := kem.Decrypt(sk, c)
	require.Nil(err)
	require.True(bytes.Equal(ka, kb))
}
