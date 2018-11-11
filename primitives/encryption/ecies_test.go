// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package encryption

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestECIES(t *testing.T) {
	require := require.New(t)

	ecies := NewECIES(elliptic.P256())

	pk, sk, err := ecies.Generate(nil)
	require.Nil(err)

	msg := []byte("ecies")

	ct, err := ecies.Encrypt(pk, msg)
	require.Nil(err)
	pt, err := ecies.Decrypt(sk, ct)
	require.Nil(err)
	require.True(bytes.Equal(msg, pt))
}

func TestEciesKEM(t *testing.T) {
	require := require.New(t)

	ecies := NewECIES(elliptic.P256())

	seed := make([]byte, 512)
	rand.Read(seed)

	pk, sk, err := ecies.Generate(seed)
	require.Nil(err)

	ka, c, err := ecies.Encapsulate(pk)
	require.Nil(err)
	kb, err := ecies.Decapsulate(sk, c)
	require.Nil(err)
	require.True(bytes.Equal(ka, kb))
}
