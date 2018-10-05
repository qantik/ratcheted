package hibe

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBoneh(t *testing.T) {
	require := require.New(t)

	b := NewBoneh()

	var seed [128]byte
	rand.Read(seed[:])

	params, root, err := b.Setup(seed[:])
	require.Nil(err)
	fmt.Println(params, root)
}
