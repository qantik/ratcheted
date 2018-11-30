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
	gcm   = encryption.NewGCM()

	bark     = NewBARK(NewUni(&signcryption{ecies, ecdsa}))
	liteBARK = NewBARK(NewLiteUni(gcm))
)

func alt(bark *BARK, n int, b *testing.B) {
	require := require.New(b)

	alice, bob, err := bark.Init()
	require.Nil(err)

	for i := 0; i < n/2; i++ {
		ka, ct, err := bark.Send(alice)
		require.Nil(err)

		kb, err := bark.Receive(bob, ct)
		require.Nil(err)
		require.True(bytes.Equal(ka, kb))

		ka, ct, err = bark.Send(bob)
		require.Nil(err)

		kb, err = bark.Receive(alice, ct)
		require.Nil(err)
		require.True(bytes.Equal(ka, kb))
	}
}

func deferredUni(bark *BARK, n int, b *testing.B) {
	require := require.New(b)

	alice, bob, err := bark.Init()
	require.Nil(err)

	var ks, cts [1000][]byte
	for i := 0; i < n/2; i++ {
		ka, ct, err := bark.Send(alice)
		require.Nil(err)

		ks[i] = ka
		cts[i] = ct
	}

	for i := 0; i < n/2; i++ {
		ka, ct, err := bark.Send(bob)
		require.Nil(err)

		kb, err := bark.Receive(alice, ct)
		require.Nil(err)
		require.True(bytes.Equal(ka, kb))
	}

	for i := 0; i < n/2; i++ {
		kb, err := bark.Receive(bob, cts[i])
		require.Nil(err)
		require.True(bytes.Equal(ks[i], kb))
	}
}

func uni(bark *BARK, n int, b *testing.B) {
	require := require.New(b)

	alice, bob, err := bark.Init()
	require.Nil(err)

	for i := 0; i < n/2; i++ {
		ka, ct, err := bark.Send(alice)
		require.Nil(err)

		kb, err := bark.Receive(bob, ct)
		require.Nil(err)
		require.True(bytes.Equal(ka, kb))
	}

	for i := 0; i < n/2; i++ {
		ka, ct, err := bark.Send(bob)
		require.Nil(err)

		kb, err := bark.Receive(alice, ct)
		require.Nil(err)
		require.True(bytes.Equal(ka, kb))
	}
}

func benchmarkAlt(bark *BARK, i int, b *testing.B) {
	for n := 0; n < b.N; n++ {
		alt(bark, i, b)
	}
}

func benchmarkUni(bark *BARK, i int, b *testing.B) {
	for n := 0; n < b.N; n++ {
		uni(bark, i, b)
	}
}

func benchmarkDeferredUni(bark *BARK, i int, b *testing.B) {
	for n := 0; n < b.N; n++ {
		deferredUni(bark, i, b)
	}
}

func BenchmarkAlt50(b *testing.B)  { benchmarkAlt(bark, 50, b) }
func BenchmarkAlt100(b *testing.B) { benchmarkAlt(bark, 100, b) }
func BenchmarkAlt200(b *testing.B) { benchmarkAlt(bark, 200, b) }
func BenchmarkAlt300(b *testing.B) { benchmarkAlt(bark, 300, b) }
func BenchmarkAlt400(b *testing.B) { benchmarkAlt(bark, 400, b) }
func BenchmarkAlt500(b *testing.B) { benchmarkAlt(bark, 500, b) }
func BenchmarkAlt600(b *testing.B) { benchmarkAlt(bark, 600, b) }
func BenchmarkAlt700(b *testing.B) { benchmarkAlt(bark, 700, b) }
func BenchmarkAlt800(b *testing.B) { benchmarkAlt(bark, 800, b) }
func BenchmarkAlt900(b *testing.B) { benchmarkAlt(bark, 900, b) }

func BenchmarkUni50(b *testing.B)  { benchmarkUni(liteBARK, 50, b) }
func BenchmarkUni100(b *testing.B) { benchmarkUni(liteBARK, 100, b) }
func BenchmarkUni200(b *testing.B) { benchmarkUni(liteBARK, 200, b) }
func BenchmarkUni300(b *testing.B) { benchmarkUni(liteBARK, 300, b) }
func BenchmarkUni400(b *testing.B) { benchmarkUni(liteBARK, 400, b) }
func BenchmarkUni500(b *testing.B) { benchmarkUni(liteBARK, 500, b) }
func BenchmarkUni600(b *testing.B) { benchmarkUni(liteBARK, 600, b) }
func BenchmarkUni700(b *testing.B) { benchmarkUni(liteBARK, 700, b) }
func BenchmarkUni800(b *testing.B) { benchmarkUni(liteBARK, 800, b) }
func BenchmarkUni900(b *testing.B) { benchmarkUni(liteBARK, 900, b) }

func BenchmarkDeferredUni50(b *testing.B)  { benchmarkDeferredUni(liteBARK, 50, b) }
func BenchmarkDeferredUni100(b *testing.B) { benchmarkDeferredUni(liteBARK, 100, b) }
func BenchmarkDeferredUni200(b *testing.B) { benchmarkDeferredUni(liteBARK, 200, b) }
func BenchmarkDeferredUni300(b *testing.B) { benchmarkDeferredUni(liteBARK, 300, b) }
func BenchmarkDeferredUni400(b *testing.B) { benchmarkDeferredUni(liteBARK, 400, b) }
func BenchmarkDeferredUni500(b *testing.B) { benchmarkDeferredUni(liteBARK, 500, b) }
func BenchmarkDeferredUni600(b *testing.B) { benchmarkDeferredUni(liteBARK, 600, b) }
func BenchmarkDeferredUni700(b *testing.B) { benchmarkDeferredUni(liteBARK, 700, b) }
func BenchmarkDeferredUni800(b *testing.B) { benchmarkDeferredUni(liteBARK, 800, b) }
func BenchmarkDeferredUni900(b *testing.B) { benchmarkDeferredUni(liteBARK, 900, b) }
