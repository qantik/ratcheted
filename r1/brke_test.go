// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package r1

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBRKE(t *testing.T) {
	require := require.New(t)

	gentry := NewGentryKEM(rand.Reader)
	lamport := NewLamportOTS(rand.Reader, sha256.New)
	srke := NewSRKE(gentry, lamport)
	sender, receiver := srke.init()

	brke := NewBRKE(srke, sender, receiver, lamport)

	ad := []byte{1, 2, 3}

	for i := 0; i < 10; i++ {
		ka, vfk, sigma, c1, c2 := brke.send(ad)
		kb := brke.receive(ad, vfk, sigma, c1, c2)

		require.True(bytes.Equal(ka, kb))
	}
}
