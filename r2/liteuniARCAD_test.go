// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package r2

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLiteUni(t *testing.T) {
	lu := NewLiteUniARCAD()

	s, r, err := lu.Init()
	require.Nil(t, err)

	pt := []byte{1, 2, 3}
	ad := []byte{100, 200}

	su, ct, err := lu.Send(s, ad, pt)
	require.Nil(t, err)

	ru, pt1, err := lu.Receive(r, ad, ct)
	require.Nil(t, err)
	require.True(t, bytes.Equal(su, ru))
	require.True(t, bytes.Equal(pt, pt1))
}
