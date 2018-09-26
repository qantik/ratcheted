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
	pa := NewBRKE(srke, sender, receiver, lamport)

	pb := NewBRKE(srke, sender, receiver, lamport)

	ad := []byte{1, 2, 3}

	add := make([][]byte, 20)
	for i := range add {
		add[i] = ad
	}

	for i := 0; i < 20; i++ {
		ka, vfk, sigma, c1, c2 := pa.send(ad)
		kb := pb.receive(ad, vfk, sigma, c1, c2)

		require.True(bytes.Equal(ka, kb))
	}

	//var kas [][]byte
	//var vfks [][]byte
	//var sigmas [][]byte
	//var c1s [][][]byte
	//var c2s [][][]byte

	//for i := range add {
	//	ka, vfk, sigma, c1, c2 := pa.send(add[i])
	//	kas = append(kas, ka)
	//	vfks = append(vfks, vfk)
	//	sigmas = append(sigmas, sigma)
	//	c1s = append(c1s, c1)
	//	c2s = append(c2s, c2)
	//}

	//for i := range add {
	//	k := pb.receive(ad, vfks[i], sigmas[i], c1s[i], c2s[i])
	//	require.True(bytes.Equal(k, kas[i]))
	//}
}
