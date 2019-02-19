// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package encryption

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAES(t *testing.T) {
	aes := NewAES()

	msg := []byte("aes-cbc")

	k, err := aes.Generate(nil)
	require.Nil(t, err)

	ct, err := aes.Encrypt(k, msg)
	require.Nil(t, err)

	pt, err := aes.Decrypt(k, ct)
	require.Nil(t, err)
	require.True(t, bytes.Equal(msg, pt))
}
