// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package encryption

import (
	"bytes"
	"crypto/elliptic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestECIES(t *testing.T) {
	require := require.New(t)

	ecies := NewECIES(elliptic.P256())

	pk, sk, err := ecies.Generate()
	require.Nil(err)

	msg := []byte("ecies")

	ct, err := ecies.Encrypt(pk, msg)
	require.Nil(err)
	pt, err := ecies.Decrypt(sk, ct)
	require.Nil(err)
	require.True(bytes.Equal(msg, pt))
}
