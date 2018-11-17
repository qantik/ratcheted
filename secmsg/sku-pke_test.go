// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package secmsg

import (
	"bytes"
	"crypto/elliptic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSKUPKE(t *testing.T) {
	require := require.New(t)

	skupke := &skuPKE{elliptic.P256()}

	msg := []byte("sku-pke")

	pk, sk, err := skupke.generate()
	require.Nil(err)

	c1, c2, err := skupke.encrypt(pk, msg)
	require.Nil(err)

	pt, err := skupke.decrypt(sk, c1, c2)
	require.Nil(err)
	require.True(bytes.Equal(msg, pt))

	upk, usk, err := skupke.updateGen()
	require.Nil(err)

	pk, err = skupke.updatePK(upk, pk)
	require.Nil(err)
	sk, err = skupke.updateSK(usk, sk)
	require.Nil(err)

	c1, c2, err = skupke.encrypt(pk, msg)
	require.Nil(err)

	pt, err = skupke.decrypt(sk, c1, c2)
	require.Nil(err)
	require.True(bytes.Equal(msg, pt))
}
