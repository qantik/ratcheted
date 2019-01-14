// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package dv

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

var pt = []byte{
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
}

func TestUniARCAD(t *testing.T) {
	uni := &uniARCAD{&signcryption{ecies, ecdsa}}

	s, r, err := uni.Init()
	require.Nil(t, err)

	for i := 0; i < 10; i++ {
		ss, ct, err := uni.Send(s, pt, pt, true)
		require.Nil(t, err)

		rr, msg, err := uni.Receive(r, pt, ct)
		require.Nil(t, err)
		require.True(t, bytes.Equal(pt, msg))

		s, r = ss, rr
	}
}
