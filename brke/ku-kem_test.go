// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package brke

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/qantik/ratcheted/primitives/hibe"
)

func TestKEM(t *testing.T) {
	require := require.New(t)

	kem := &kuKEM{hibe.NewGentry()}

	var seed [128]byte
	rand.Read(seed[:])

	pk, sk, err := kem.generate(seed[:])
	require.Nil(err)

	ka, c, err := kem.encrypt(pk)
	require.Nil(err)

	kb, err := kem.decrypt(sk, c)
	require.Nil(err)
	require.True(bytes.Equal(ka, kb))
}
