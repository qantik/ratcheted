// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package secmsg

import (
	"bytes"
	"crypto/elliptic"
	"testing"

	"github.com/qantik/ratcheted/primitives/encryption"
	"github.com/stretchr/testify/require"
)

func TestHkuPKE(t *testing.T) {
	require := require.New(t)

	hku := hkuPKE{pke: encryption.NewECIES(elliptic.P256()), sku: &skuPKE{elliptic.P256()}}

	msg := []byte("hku-PKE")
	ad := []byte("associated-data")

	s, r, err := hku.generate()
	require.Nil(err)

	for i := 0; i < 10; i++ {
		ss, ct, err := hku.encrypt(s, msg, ad)
		require.Nil(err)

		rr, pt, err := hku.decrypt(r, ct, ad)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))

		s, r = ss, rr
	}
}
