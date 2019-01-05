// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package dratch

import (
	"bytes"
	"crypto/elliptic"
	"fmt"
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

	dr   = NewDRatch(gcm, nil, nil)
	drpk = NewDRatch(gcm, ecies, ecdsa)

	msg = []byte{
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
	}
)

func alt(dr *DRatch, n int, b *testing.B) {
	require := require.New(b)

	alice, bob, err := dr.Init()
	require.Nil(err)

	max := 0
	maxs := 0

	for i := 0; i < n/2; i++ {
		ct, err := dr.Send(alice, msg)
		require.Nil(err)

		if len(ct) > max {
			max = len(ct)
		}
		if alice.size() > maxs {
			maxs = alice.size()
		}
		if bob.size() > maxs {
			maxs = bob.size()
		}

		pt, err := dr.Receive(bob, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))

		ct, err = dr.Send(bob, msg)
		require.Nil(err)

		if len(ct) > max {
			max = len(ct)
		}
		if alice.size() > maxs {
			maxs = alice.size()
		}
		if bob.size() > maxs {
			maxs = bob.size()
		}

		pt, err = dr.Receive(alice, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}

	fmt.Println("size:", max)
	fmt.Println("state:", maxs)
}

func uni(dr *DRatch, n int, b *testing.B) {
	require := require.New(b)

	alice, bob, err := dr.Init()
	require.Nil(err)

	max := 0
	maxs := 0

	for i := 0; i < n/2; i++ {
		ct, err := dr.Send(alice, msg)
		require.Nil(err)
		if len(ct) > max {
			max = len(ct)
		}

		pt, err := dr.Receive(bob, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))

		if alice.size() > maxs {
			maxs = alice.size()
		}
		if bob.size() > maxs {
			maxs = bob.size()
		}

	}

	for i := 0; i < n/2; i++ {
		ct, err := dr.Send(bob, msg)
		require.Nil(err)
		if len(ct) > max {
			max = len(ct)
		}

		pt, err := dr.Receive(alice, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
		if alice.size() > maxs {
			maxs = alice.size()
		}
		if bob.size() > maxs {
			maxs = bob.size()
		}
	}

	fmt.Println("size:", max)
	fmt.Println("state:", maxs)
}

func deferredUni(dr *DRatch, n int, b *testing.B) {
	require := require.New(b)

	//msg := []byte("dratch")

	alice, bob, err := dr.Init()
	require.Nil(err)

	var cts [1000][]byte
	for i := 0; i < n/2; i++ {
		ct, err := dr.Send(alice, msg)
		require.Nil(err)

		cts[i] = ct
	}

	for i := 0; i < n/2; i++ {
		ct, err := dr.Send(bob, msg)
		require.Nil(err)

		pt, err := dr.Receive(alice, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}

	for i := 0; i < n/2; i++ {
		pt, err := dr.Receive(bob, cts[i])
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}
}

func benchmarkAlt(dr *DRatch, i int, b *testing.B) {
	for n := 0; n < 1; n++ {
		alt(dr, i, b)
	}
	fmt.Println(ckaGen, fsGen)
}

func benchmarkUni(dr *DRatch, i int, b *testing.B) {
	for n := 0; n < b.N; n++ {
		uni(dr, i, b)
	}
	fmt.Println(ckaGen, fsGen)
}

func benchmarkDeferredUni(dr *DRatch, i int, b *testing.B) {
	for n := 0; n < b.N; n++ {
		deferredUni(dr, i, b)
	}
	fmt.Println(ckaGen, fsGen)
}

//func BenchmarkAlt50(b *testing.B)  { benchmarkAlt(dr, 50, b) }
//func BenchmarkAlt100(b *testing.B) { benchmarkAlt(dr, 100, b) }
//func BenchmarkAlt200(b *testing.B) { benchmarkAlt(dr, 200, b) }
//func BenchmarkAlt300(b *testing.B) { benchmarkAlt(dr, 300, b) }
//func BenchmarkAlt400(b *testing.B) { benchmarkAlt(dr, 400, b) }
//func BenchmarkAlt500(b *testing.B) { benchmarkAlt(dr, 500, b) }
//func BenchmarkAlt600(b *testing.B) { benchmarkAlt(dr, 600, b) }
//func BenchmarkAlt700(b *testing.B) { benchmarkAlt(dr, 700, b) }
//func BenchmarkAlt800(b *testing.B) { benchmarkAlt(dr, 800, b) }
//func BenchmarkAlt900(b *testing.B) { benchmarkAlt(dr, 900, b) }

func BenchmarkUni50(b *testing.B)  { benchmarkUni(drpk, 50, b) }
func BenchmarkUni100(b *testing.B) { benchmarkUni(drpk, 100, b) }
func BenchmarkUni200(b *testing.B) { benchmarkUni(drpk, 200, b) }
func BenchmarkUni300(b *testing.B) { benchmarkUni(drpk, 300, b) }
func BenchmarkUni400(b *testing.B) { benchmarkUni(drpk, 400, b) }
func BenchmarkUni500(b *testing.B) { benchmarkUni(drpk, 500, b) }
func BenchmarkUni600(b *testing.B) { benchmarkUni(drpk, 600, b) }
func BenchmarkUni700(b *testing.B) { benchmarkUni(drpk, 700, b) }
func BenchmarkUni800(b *testing.B) { benchmarkUni(drpk, 800, b) }
func BenchmarkUni900(b *testing.B) { benchmarkUni(drpk, 900, b) }

//func BenchmarkDeferredUni50(b *testing.B) { benchmarkDeferredUni(dr, 50, b) }
//func BenchmarkDeferredUni100(b *testing.B) { benchmarkDeferredUni(dr, 100, b) }
//func BenchmarkDeferredUni200(b *testing.B) { benchmarkDeferredUni(dr, 200, b) }
//func BenchmarkDeferredUni300(b *testing.B) { benchmarkDeferredUni(dr, 300, b) }
//func BenchmarkDeferredUni400(b *testing.B) { benchmarkDeferredUni(dr, 400, b) }
//func BenchmarkDeferredUni500(b *testing.B) { benchmarkDeferredUni(dr, 500, b) }
//func BenchmarkDeferredUni600(b *testing.B) { benchmarkDeferredUni(dr, 600, b) }
//func BenchmarkDeferredUni700(b *testing.B) { benchmarkDeferredUni(dr, 700, b) }
//func BenchmarkDeferredUni800(b *testing.B) { benchmarkDeferredUni(dr, 800, b) }
//func BenchmarkDeferredUni900(b *testing.B) { benchmarkDeferredUni(dr, 900, b) }
