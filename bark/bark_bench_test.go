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

	bark := NewBARK(NewUni(&signcryption{ecies, ecdsa}))
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
	pa, pb, err := bark.Init()
	require.Nil(err)
	var ks, cts [1000][]byte
	for i := 0; i < n/2; i++ {
		pau, ka, ct, err := bark.Send(pa)
		require.Nil(err)

		cts[i] = ct
		ks[i] = ka
		pa = pau
	}

	for i := 0; i < n/4; i++ {
		pbu, kb, err := bark.Receive(pb, cts[i])
		require.Nil(err)
		require.True(bytes.Equal(ks[i], kb))

		pb = pbu
	}

	for i := n / 2; i < n; i++ {
		pbu, kb, ct, err := bark.Send(pb)
		require.Nil(err)

		cts[i] = ct
		ks[i] = kb
		pb = pbu
	}

	for i := n / 2; i < n; i++ {
		pau, kb, err := bark.Receive(pa, cts[i])
		require.Nil(err)
		require.True(bytes.Equal(ks[i], kb))

		pa = pau
	}

	for i := n / 4; i < n/2; i++ {
		pbu, kb, err := bark.Receive(pb, cts[i])
		require.Nil(err)
		require.True(bytes.Equal(ks[i], kb))

		pb = pbu
	}
}

func benchmarkBARKUnidirectional(i int, b *testing.B) {
	for n := 0; n < b.N; n++ {
		barkUnidirectional(i, b)
	}
}

//func BenchmarkBARKSingle50(b *testing.B)  { benchmarkBARKSingle(50, b) }
//func BenchmarkBARKSingle100(b *testing.B) { benchmarkBARKSingle(100, b) }
//func BenchmarkBARKSingle200(b *testing.B) { benchmarkBARKSingle(200, b) }
//func BenchmarkBARKSingle300(b *testing.B) { benchmarkBARKSingle(300, b) }
//func BenchmarkBARKSingle400(b *testing.B) { benchmarkBARKSingle(400, b) }
//func BenchmarkBARKSingle500(b *testing.B) { benchmarkBARKSingle(500, b) }
//func BenchmarkBARKSingle600(b *testing.B) { benchmarkBARKSingle(600, b) }
//func BenchmarkBARKSingle700(b *testing.B) { benchmarkBARKSingle(700, b) }
//func BenchmarkBARKSingle800(b *testing.B) { benchmarkBARKSingle(800, b) }
//func BenchmarkBARKSingle900(b *testing.B) { benchmarkBARKSingle(900, b) }

//func BenchmarkBARKLiteSingle50(b *testing.B)  { benchmarkBARKLiteSingle(50, b) }
//func BenchmarkBARKLiteSingle100(b *testing.B) { benchmarkBARKLiteSingle(100, b) }
//func BenchmarkBARKLiteSingle200(b *testing.B) { benchmarkBARKLiteSingle(200, b) }
//func BenchmarkBARKLiteSingle300(b *testing.B) { benchmarkBARKLiteSingle(300, b) }
//func BenchmarkBARKLiteSingle400(b *testing.B) { benchmarkBARKLiteSingle(400, b) }
//func BenchmarkBARKLiteSingle500(b *testing.B) { benchmarkBARKLiteSingle(500, b) }
//func BenchmarkBARKLiteSingle600(b *testing.B) { benchmarkBARKLiteSingle(600, b) }
//func BenchmarkBARKLiteSingle700(b *testing.B) { benchmarkBARKLiteSingle(700, b) }
//func BenchmarkBARKLiteSingle800(b *testing.B) { benchmarkBARKLiteSingle(800, b) }
//func BenchmarkBARKLiteSingle900(b *testing.B) { benchmarkBARKLiteSingle(900, b) }

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

//func BenchmarkBARKLiteDual50(b *testing.B)  { benchmarkBARKLiteDual(50, b) }
//func BenchmarkBARKLiteDual100(b *testing.B) { benchmarkBARKLiteDual(100, b) }
//func BenchmarkBARKLiteDual200(b *testing.B) { benchmarkBARKLiteDual(200, b) }
//func BenchmarkBARKLiteDual300(b *testing.B) { benchmarkBARKLiteDual(300, b) }
//func BenchmarkBARKLiteDual400(b *testing.B) { benchmarkBARKLiteDual(400, b) }
//func BenchmarkBARKLiteDual500(b *testing.B) { benchmarkBARKLiteDual(500, b) }
//func BenchmarkBARKLiteDual600(b *testing.B) { benchmarkBARKLiteDual(600, b) }
//func BenchmarkBARKLiteDual700(b *testing.B) { benchmarkBARKLiteDual(700, b) }
//func BenchmarkBARKLiteDual800(b *testing.B) { benchmarkBARKLiteDual(800, b) }
//func BenchmarkBARKLiteDual900(b *testing.B) { benchmarkBARKLiteDual(900, b) }
