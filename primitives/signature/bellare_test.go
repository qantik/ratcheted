// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package signature

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBellare(t *testing.T) {
	require := require.New(t)

	b := NewBellare()
	pk, sk, err := b.Generate()
	require.Nil(err)

	msg := []byte("bellare")

	for i := 0; i < bellareMaxPeriod; i++ {
		sig, err := b.Sign(sk, msg)
		require.Nil(err)
		require.Nil(b.Verify(pk, msg, sig))

		sk, err = b.Update(sk)
		require.Nil(err)
	}
}
