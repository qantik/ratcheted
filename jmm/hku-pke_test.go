// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package jmm

import (
	"bytes"
	"crypto/elliptic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/qantik/ratcheted/primitives/encryption"
)

func TestHkuPKE(t *testing.T) {
	require := require.New(t)

	curve := elliptic.P256()

	hku := hkuPKE{pke: encryption.NewECIES(curve), sku: &skuPKE{curve}}

	msg := []byte("hku-PKE")
	ad := []byte("associated-data")

	s, r, err := hku.generate()
	require.Nil(err)

	for i := 0; i < 10; i++ {
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

		rr, inf1, err := hku.updateDK(rr)
		require.Nil(err)
		rr, inf2, err := hku.updateDK(rr)
		require.Nil(err)

		ss, err = hku.updateEK(ss, inf1)
		require.Nil(err)
		ss, err = hku.updateEK(ss, inf2)
		require.Nil(err)

		rr, pt, err = hku.decrypt(rr, ct2, ad)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))

		rr, pt, err = hku.decrypt(rr, ct3, ad)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))

		rr, pt, err = hku.decrypt(rr, ct4, ad)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))

		ss, ct, err := hku.encrypt(ss, msg, ad)
		require.Nil(err)

		rr, pt, err = hku.decrypt(rr, ct, ad)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))

		s, r = ss, rr
	}
}
