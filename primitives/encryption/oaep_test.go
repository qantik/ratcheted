// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package encryption

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOAEP(t *testing.T) {
	require := require.New(t)

	oaep := NewOAEP()

	msg := []byte("rsa-oaep")
	ad := []byte("associated-data")

	seed := make([]byte, 16)
	rand.Read(seed)

	pk, sk, err := oaep.Generate(seed)
	require.Nil(err)

	ct, err := oaep.Encrypt(pk, msg, ad)
	require.Nil(err)

	pt, err := oaep.Decrypt(sk, ct, ad)
	require.Nil(err)
	require.True(bytes.Equal(msg, pt))
}
