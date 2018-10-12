// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package encryption

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGCM(t *testing.T) {
	require := require.New(t)

	gcm := NewGCM()

	msg := []byte("aes-gcm")
	ad := []byte("associated")

	var key [16]byte
	rand.Read(key[:])

	ct, err := gcm.Encrypt(key[:], msg, ad)
	require.Nil(err)

	pt, err := gcm.Decrypt(key[:], ct, ad)
	require.Nil(err)
	require.True(bytes.Equal(msg, pt))
}
