// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package dratch

import (
	"fmt"
	"testing"

	"github.com/qantik/ratcheted/primitives/encryption"
	"github.com/stretchr/testify/require"
)

func TestDRatch(t *testing.T) {
	require := require.New(t)

	dr := NewDRatch(encryption.NewGCM())

	a, b, err := dr.Init()
	require.Nil(err)
	fmt.Println(a, b)
}
