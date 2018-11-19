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

	for i := 0; i < 3; i++ {
		ss, ct1, err := hku.encrypt(s, msg, ad)
		require.Nil(err)
		ss, ct2, err := hku.encrypt(ss, msg, ad)
		require.Nil(err)
		ss, ct3, err := hku.encrypt(ss, msg, ad)
		require.Nil(err)
		ss, ct4, err := hku.encrypt(ss, msg, ad)
		require.Nil(err)

		rr, pt, err := hku.decrypt(r, ct1, ad)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))

		rrr, inf1, err := hku.updateDK(rr)
		require.Nil(err)
		rrr, inf2, err := hku.updateDK(rrr)
		require.Nil(err)

		ss, err = hku.updateEK(ss, inf1)
		require.Nil(err)
		ss, err = hku.updateEK(ss, inf2)
		require.Nil(err)

		rrr, pt, err = hku.decrypt(rrr, ct2, ad)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
		rrr, pt, err = hku.decrypt(rrr, ct3, ad)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
		rrr, pt, err = hku.decrypt(rrr, ct4, ad)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))

		ss, ct, err := hku.encrypt(ss, msg, ad)
		require.Nil(err)

		rrr, pt, err = hku.decrypt(rrr, ct, ad)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))

		s, r = ss, rrr
	}
}
