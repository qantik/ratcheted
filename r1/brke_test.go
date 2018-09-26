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

func TestBRKE1(t *testing.T) {
	require := require.New(t)

	gentry := NewGentryKEM(rand.Reader)
	lamport := NewLamportOTS(rand.Reader, sha256.New)
	srke := NewSRKE(gentry, lamport)
	sender, receiver := srke.init()

	brke := NewBRKE(srke, sender, receiver, lamport)

	ad := []byte{1, 2, 3}

	for i := 0; i < 48; i++ {
		ka, vfk, sigma, c1, c2 := brke.send(ad)
		kb := brke.receive(ad, vfk, sigma, c1, c2)

		require.True(bytes.Equal(ka, kb))
	}
}

func TestBRKE2(t *testing.T) {
	require := require.New(t)

	gentry := NewGentryKEM(rand.Reader)
	lamport := NewLamportOTS(rand.Reader, sha256.New)
	srke := NewSRKE(gentry, lamport)
	sender, receiver := srke.init()

	brke := NewBRKE(srke, sender, receiver, lamport)

	ad := []byte{1, 2, 3}

	for i := 0; i < 16; i++ {
		ka, vfk, sigma, c1, c2 := brke.send(ad)
		ka2, vfk2, sigma2, c11, c22 := brke.send(ad)
		ka3, vfk3, sigma3, c111, c222 := brke.send(ad)
		kb := brke.receive(ad, vfk, sigma, c1, c2)
		kb2 := brke.receive(ad, vfk2, sigma2, c11, c22)
		kb3 := brke.receive(ad, vfk3, sigma3, c111, c222)

		require.True(bytes.Equal(ka, kb))
		require.True(bytes.Equal(ka2, kb2))
		require.True(bytes.Equal(ka3, kb3))
	}
}

func TestBRKE3(t *testing.T) {
	require := require.New(t)

	gentry := NewGentryKEM(rand.Reader)
	lamport := NewLamportOTS(rand.Reader, sha256.New)
	srke := NewSRKE(gentry, lamport)
	sender, receiver := srke.init()

	brke1 := NewBRKE(srke, sender, receiver, lamport)
	brke2 := NewBRKE(srke, sender, receiver, lamport)

	ad := []byte{1, 2, 3}

	for i := 0; i < 10; i++ {
		ka, vfk, sigma, c1, c2 := brke1.send(ad)
		kb := brke2.receive(ad, vfk, sigma, c1, c2)

		require.True(bytes.Equal(ka, kb))
	}
}

func bb(j int, b *testing.B) {
	require := require.New(b)

	b.StopTimer()
	gentry := NewGentryKEM(rand.Reader)
	lamport := NewLamportOTS(rand.Reader, sha256.New)

	srke1 := NewSRKE(gentry, lamport)
	sa, ra := srke1.init()
	//srke2 := NewSRKE(gentry, lamport)
	//sb, rb := srke2.init()

	brke1 := NewBRKE(srke1, sa, ra, lamport)
	//brke2 := NewBRKE(srke2, sb, rb, lamport)

	ad := []byte{1, 2, 3}

	add := make([][]byte, j)
	for i := range add {
		add[i] = ad
	}

	b.StartTimer()
	var kas [][]byte
	var vfks [][]byte
	var sigmas [][]byte
	var c1s [][][]byte
	var c2s [][][]byte

	for i := range add {
		ka, vfk, sigma, c1, c2 := brke1.send(add[i])
		b.StopTimer()
		kas = append(kas, ka)
		vfks = append(vfks, vfk)
		sigmas = append(sigmas, sigma)
		c1s = append(c1s, c1)
		c2s = append(c2s, c2)
		b.StartTimer()
	}

	for i := range add {
		k := brke1.receive(ad, vfks[i], sigmas[i], c1s[i], c2s[i])
		require.True(bytes.Equal(k, kas[i]))
	}
}

func BenchmarkBERK(b *testing.B) {
	for n := 0; n < b.N; n++ {
		bb(30, b)
	}
}
