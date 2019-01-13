// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package dv

import (
	"bytes"
	"crypto/elliptic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/qantik/ratcheted/primitives/encryption"
	"github.com/qantik/ratcheted/primitives/signature"
)

func TestSigncryption(t *testing.T) {
	c := elliptic.P256()

	ecies := encryption.NewECIES(c)
	ecdsa := signature.NewECDSA(c)
	sc := &signcryption{ecies, ecdsa}

	sks, skr, err := sc.generateSignKeys()
	require.Nil(t, err)
	pks, pkr, err := sc.generateCipherKeys()
	require.Nil(t, err)

	msg := make([]byte, 3)
	msg[0] = 1
	msg[1] = 2
	msg[2] = 3

	ad := []byte{100, 200}

	ct, err := sc.signcrypt(sks, pkr, ad, msg)
	require.Nil(t, err)

	pt, err := sc.unsigncrypt(skr, pks, ad, ct)
	require.Nil(t, err)
	require.True(t, bytes.Equal(msg, pt))
}
