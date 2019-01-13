// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package acd

import (
	"bytes"
	"crypto/elliptic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCKA(t *testing.T) {
	require := require.New(t)

	cka := cka{curve: elliptic.P256()}

	sa, sb, err := cka.generate()
	require.Nil(err)

	for i := 0; i < 10; i++ {
		usa, msg, ka, err := cka.send(sa)
		require.Nil(err)

		usb, kb, err := cka.receive(sb, msg)
		require.Nil(err)
		require.True(bytes.Equal(ka, kb))

		sa, sb = usb, usa
	}
}
