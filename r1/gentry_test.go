// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package r1

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGentry(t *testing.T) {
	require := require.New(t)

	pk, sk := gen()

	ad := []byte{1, 2, 3}

	for i := 0; i < 10; i++ {
		Ka, C := pk.enc()
		Kb := sk.dec(C)
		require.True(Ka.Equals(Kb))

		pk.update(ad)
		sk.update(ad)
	}
}
