// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package signature

import (
	"crypto/elliptic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestECDSA(t *testing.T) {
	require := require.New(t)

	ecdsa := NewECDSA(elliptic.P256())

	pk, sk, err := ecdsa.Generate()
	require.Nil(err)

	msg := []byte("ecdsa")

	sig, err := ecdsa.Sign(sk, msg)
	require.Nil(err)

	require.Nil(ecdsa.Verify(pk, msg, sig))
	require.NotNil(ecdsa.Verify(pk, []byte("abc"), sig))
}
