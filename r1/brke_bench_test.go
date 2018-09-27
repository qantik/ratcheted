package r1

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	gentry  = NewGentryKEM(rand.Reader)
	lamport = NewLamportOTS(rand.Reader, sha256.New)

	ad = []byte{1, 2, 3}
)

func brkeSingle(n int, b *testing.B) {
	require := require.New(b)

	srke := NewSRKE(gentry, lamport)
	sender, receiver := srke.init()

	pa := NewBRKE(srke, sender, receiver, lamport)
	pb := NewBRKE(srke, sender, receiver, lamport)

	//for i := 0; i < n; i++ {
	//	ka, vfk, sigma, c1, c2 := pa.send(ad)
	//	kb := pb.receive(ad, vfk, sigma, c1, c2)

	//	require.True(bytes.Equal(ka, kb))
	//}

	var kas [][]byte
	var vfks [][]byte
	var sigmas [][]byte
	var c1s [][][]byte
	var c2s [][][]byte

	//b.ResetTimer()
	for i := 0; i < n; i++ {
		ka, vfk, sigma, c1, c2 := pa.send(ad)

		b.StopTimer()
		kas = append(kas, ka)
		vfks = append(vfks, vfk)
		sigmas = append(sigmas, sigma)
		c1s = append(c1s, c1)
		c2s = append(c2s, c2)
		b.StartTimer()
	}

	for i := 0; i < n; i++ {
		k := pb.receive(ad, vfks[i], sigmas[i], c1s[i], c2s[i])
		require.True(bytes.Equal(k, kas[i]))
	}
}

func benchmarkBRKESingle(i int, b *testing.B) {
	for n := 0; n < b.N; n++ {
		brkeSingle(i, b)
	}
}

func BenchmarkBRKESingle50(b *testing.B)  { benchmarkBRKESingle(50, b) }
func BenchmarkBRKESingle100(b *testing.B) { benchmarkBRKESingle(100, b) }
func BenchmarkBRKESingle200(b *testing.B) { benchmarkBRKESingle(200, b) }
func BenchmarkBRKESingle300(b *testing.B) { benchmarkBRKESingle(300, b) }
func BenchmarkBRKESingle400(b *testing.B) { benchmarkBRKESingle(400, b) }
func BenchmarkBRKESingle500(b *testing.B) { benchmarkBRKESingle(500, b) }
func BenchmarkBRKESingle600(b *testing.B) { benchmarkBRKESingle(600, b) }
func BenchmarkBRKESingle700(b *testing.B) { benchmarkBRKESingle(700, b) }
func BenchmarkBRKESingle800(b *testing.B) { benchmarkBRKESingle(800, b) }
func BenchmarkBRKESingle900(b *testing.B) { benchmarkBRKESingle(900, b) }
