// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package brke

import (
	"bytes"
	"crypto/elliptic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/qantik/ratcheted/primitives/encryption"
	"github.com/qantik/ratcheted/primitives/hibe"
	"github.com/qantik/ratcheted/primitives/signature"
)

var curve = elliptic.P256()

func brkeAlternating(n int, b *testing.B) {
	require := require.New(b)

	//brke := NewBRKE(hibe.NewGentry(), signature.NewLamport(rand.Reader, sha256.New))
	brke := NewBRKE(hibe.NewGentry(), encryption.NewECIES(curve), signature.NewECDSA(curve))

	ad := []byte{1, 2, 3}

	alice, bob, err := brke.Init()
	require.Nil(err)

	for i := 0; i < n/2; i++ {
		ka, c, err := brke.Send(alice, ad)
		require.Nil(err)

		kb, err := brke.Receive(bob, ad, c)
		require.Nil(err)
		require.True(bytes.Equal(ka, kb))

		kb, c, err = brke.Send(bob, ad)
		require.Nil(err)

		ka, err = brke.Receive(alice, ad, c)
		require.Nil(err)
		require.True(bytes.Equal(ka, kb))
	}
}

func benchmarkBRKEAlternating(i int, b *testing.B) {
	for n := 0; n < b.N; n++ {
		brkeAlternating(i, b)
	}
}

func brkeUnidirectional(n int, b *testing.B) {
	require := require.New(b)

	//brke := NewBRKE(hibe.NewGentry(), signature.NewLamport(rand.Reader, sha256.New))
	brke := NewBRKE(hibe.NewGentry(), encryption.NewECIES(curve), signature.NewECDSA(curve))

	ad := []byte{1, 2, 3}

	alice, bob, err := brke.Init()
	require.Nil(err)

	for i := 0; i < n/50; i++ {
		var ks [25][]byte
		var cs [25][][]byte
		for j := 0; j < 25; j++ {
			k, c, err := brke.Send(alice, ad)
			require.Nil(err)
			ks[j] = k
			cs[j] = c
		}

		for j := 0; j < 25; j++ {
			kb, c, err := brke.Send(bob, ad)
			require.Nil(err)

			ka, err := brke.Receive(alice, ad, c)
			require.Nil(err)
			require.True(bytes.Equal(ka, kb))
		}

		for j := 0; j < 25; j++ {
			k, err := brke.Receive(bob, ad, cs[j])
			require.Nil(err)
			require.True(bytes.Equal(ks[j], k))
		}
	}
}

func benchmarkBRKEUnidirectional(i int, b *testing.B) {
	for n := 0; n < b.N; n++ {
		brkeUnidirectional(i, b)
	}
}

func BenchmarkBRKEAlternating100(b *testing.B) { benchmarkBRKEAlternating(100, b) }

//func BenchmarkBRKEAlternating200(b *testing.B) { benchmarkBRKEAlternating(200, b) }
//func BenchmarkBRKEAlternating300(b *testing.B) { benchmarkBRKEAlternating(300, b) }
//func BenchmarkBRKEAlternating400(b *testing.B) { benchmarkBRKEAlternating(400, b) }
//func BenchmarkBRKEAlternating500(b *testing.B) { benchmarkBRKEAlternating(500, b) }
//func BenchmarkBRKEAlternating600(b *testing.B) { benchmarkBRKEAlternating(600, b) }
//func BenchmarkBRKEAlternating700(b *testing.B) { benchmarkBRKEAlternating(700, b) }
//func BenchmarkBRKEAlternating800(b *testing.B) { benchmarkBRKEAlternating(800, b) }
//func BenchmarkBRKEAlternating900(b *testing.B) { benchmarkBRKEAlternating(900, b) }

func BenchmarkBRKEUnidirectional100(b *testing.B) { benchmarkBRKEUnidirectional(100, b) }

//func BenchmarkBRKEUnidirectional200(b *testing.B) { benchmarkBRKEUnidirectional(200, b) }
//func BenchmarkBRKEUnidirectional300(b *testing.B) { benchmarkBRKEUnidirectional(300, b) }
//func BenchmarkBRKEUnidirectional400(b *testing.B) { benchmarkBRKEUnidirectional(400, b) }
//func BenchmarkBRKEUnidirectional500(b *testing.B) { benchmarkBRKEUnidirectional(500, b) }
//func BenchmarkBRKEUnidirectional600(b *testing.B) { benchmarkBRKEUnidirectional(600, b) }
//func BenchmarkBRKEUnidirectional700(b *testing.B) { benchmarkBRKEUnidirectional(700, b) }
//func BenchmarkBRKEUnidirectional800(b *testing.B) { benchmarkBRKEUnidirectional(800, b) }
//func BenchmarkBRKEUnidirectional900(b *testing.B) { benchmarkBRKEUnidirectional(900, b) }
