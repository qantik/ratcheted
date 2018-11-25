// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package bark

import (
	"bytes"
	"crypto/elliptic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/qantik/ratcheted/primitives/encryption"
	"github.com/qantik/ratcheted/primitives/signature"
)

var (
	curve = elliptic.P256()
	ecies = encryption.NewECIES(curve)
	ecdsa = signature.NewECDSA(curve)
)

func barkAlternating(n int, b *testing.B) {
	require := require.New(b)

	//bark := NewBARK(NewUni(&signcryption{ecies, ecdsa}))
	uni := NewLiteUni(encryption.NewGCM())
	bark := NewBARK(uni)

	pa, pb, err := bark.Init()
	require.Nil(err)

	for i := 0; i < n/2; i++ {
		pau, ka, ct, err := bark.Send(pa)
		require.Nil(err)

		pbu, kb, err := bark.Receive(pb, ct)
		require.Nil(err)
		require.True(bytes.Equal(ka, kb))

		pbu, ka, ct, err = bark.Send(pbu)
		require.Nil(err)

		pau, kb, err = bark.Receive(pau, ct)
		require.Nil(err)
		require.True(bytes.Equal(ka, kb))

		pa, pb = pau, pbu
	}
}

func benchmarkBARKAlternating(i int, b *testing.B) {
	for n := 0; n < b.N; n++ {
		barkAlternating(i, b)
	}
}

func barkUnidirectional(n int, b *testing.B) {
	require := require.New(b)

	bark := NewBARK(NewUni(&signcryption{ecies, ecdsa}))
	//uni := NewLiteUni(encryption.NewGCM())
	//bark := NewBARK(uni)

	pa, pb, err := bark.Init()
	require.Nil(err)

	for i := 0; i < n; i++ {
		if n%11 != 0 {
			pau, ka, ct, err := bark.Send(pa)
			require.Nil(err)

			pbu, kb, err := bark.Receive(pb, ct)
			require.Nil(err)
			require.True(bytes.Equal(ka, kb))

			pa, pb = pau, pbu

		} else {
			pbu, ka, ct, err := bark.Send(pb)
			require.Nil(err)

			pau, kb, err := bark.Receive(pa, ct)
			require.Nil(err)
			require.True(bytes.Equal(ka, kb))

			pa, pb = pau, pbu
		}
	}
}

func benchmarkBARKUnidirectional(i int, b *testing.B) {
	for n := 0; n < b.N; n++ {
		barkUnidirectional(i, b)
	}
}

func BenchmarkBARKAlternating50(b *testing.B)  { benchmarkBARKAlternating(50, b) }
func BenchmarkBARKAlternating100(b *testing.B) { benchmarkBARKAlternating(100, b) }
func BenchmarkBARKAlternating200(b *testing.B) { benchmarkBARKAlternating(200, b) }
func BenchmarkBARKAlternating300(b *testing.B) { benchmarkBARKAlternating(300, b) }
func BenchmarkBARKAlternating400(b *testing.B) { benchmarkBARKAlternating(400, b) }
func BenchmarkBARKAlternating500(b *testing.B) { benchmarkBARKAlternating(500, b) }
func BenchmarkBARKAlternating600(b *testing.B) { benchmarkBARKAlternating(600, b) }
func BenchmarkBARKAlternating700(b *testing.B) { benchmarkBARKAlternating(700, b) }
func BenchmarkBARKAlternating800(b *testing.B) { benchmarkBARKAlternating(800, b) }
func BenchmarkBARKAlternating900(b *testing.B) { benchmarkBARKAlternating(900, b) }

func BenchmarkBARKUnidirectional50(b *testing.B)  { benchmarkBARKUnidirectional(50, b) }
func BenchmarkBARKUnidirectional100(b *testing.B) { benchmarkBARKUnidirectional(100, b) }
func BenchmarkBARKUnidirectional200(b *testing.B) { benchmarkBARKUnidirectional(200, b) }
func BenchmarkBARKUnidirectional300(b *testing.B) { benchmarkBARKUnidirectional(300, b) }
func BenchmarkBARKUnidirectional400(b *testing.B) { benchmarkBARKUnidirectional(400, b) }
func BenchmarkBARKUnidirectional500(b *testing.B) { benchmarkBARKUnidirectional(500, b) }
func BenchmarkBARKUnidirectional600(b *testing.B) { benchmarkBARKUnidirectional(600, b) }
func BenchmarkBARKUnidirectional700(b *testing.B) { benchmarkBARKUnidirectional(700, b) }
func BenchmarkBARKUnidirectional800(b *testing.B) { benchmarkBARKUnidirectional(800, b) }
func BenchmarkBARKUnidirectional900(b *testing.B) { benchmarkBARKUnidirectional(900, b) }
