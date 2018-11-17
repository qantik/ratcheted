// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package encryption

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOAEP(t *testing.T) {
	require := require.New(t)

	oaep := NewOAEP()

	msg := []byte("rsa-oaep")
	ad := []byte("associated-data")

	pk, sk, err := oaep.Generate(nil)
	require.Nil(err)

	ct, err := oaep.Encrypt(pk, msg, ad)
	require.Nil(err)

	pt, err := oaep.Decrypt(sk, ct, ad)
	require.Nil(err)
	require.True(bytes.Equal(msg, pt))
}
