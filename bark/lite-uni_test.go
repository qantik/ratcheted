// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package bark

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/qantik/ratcheted/primitives/encryption"
)

func TestLiteUni(t *testing.T) {
	require := require.New(t)

	lu := NewLiteUni(encryption.NewGCM())

	s, r, err := lu.Init()
	require.Nil(err)

	pt := []byte{1, 2, 3}
	ad := []byte{100, 200}

	su, ct, err := lu.Send(s, ad, pt)
	require.Nil(err)

	ru, pt1, err := lu.Receive(r, ad, ct)
	require.Nil(err)
	require.True(bytes.Equal(su, ru))
	require.True(bytes.Equal(pt, pt1))
}
