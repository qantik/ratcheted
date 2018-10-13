// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package sch

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/qantik/ratcheted/primitives/hibe"
	"github.com/qantik/ratcheted/primitives/signature"
)

func schAlternating(n int, b *testing.B) {
	require := require.New(b)

	sch := NewSCh(signature.NewBellare(), hibe.NewGentry())

	msg := []byte("sch")
	ad := []byte("associated")

	alice, bob, err := sch.Init()
	require.Nil(err)

	for i := 0; i < n/2; i++ {
		ct, err := sch.Send(alice, ad, msg)
		require.Nil(err)

		pt, err := sch.Receive(bob, ad, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))

		ct, err = sch.Send(bob, ad, msg)
		require.Nil(err)

		pt, err = sch.Receive(alice, ad, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}
}

func benchmarkSChAlternating(i int, b *testing.B) {
	for n := 0; n < b.N; n++ {
		schAlternating(i, b)
	}
}

func schUnidirectional(n int, b *testing.B) {
	require := require.New(b)

	sch := NewSCh(signature.NewBellare(), hibe.NewGentry())

	msg := []byte("sch")
	ad := []byte("associated")

	alice, bob, err := sch.Init()
	require.Nil(err)

	var cts [1000][]byte
	for i := 0; i < n/2; i++ {
		ct, err := sch.Send(alice, ad, msg)
		require.Nil(err)
		cts[i] = ct
	}

	for i := 0; i < n/2; i++ {
		ct, err := sch.Send(bob, ad, msg)
		require.Nil(err)

		pt, err := sch.Receive(alice, ad, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}

	for i := 0; i < n/2; i++ {
		pt, err := sch.Receive(bob, ad, cts[i])
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}
}

func benchmarkSChUnidirectional(i int, b *testing.B) {
	for n := 0; n < b.N; n++ {
		schUnidirectional(i, b)
	}
}

func BenchmarkSChAlternating100(b *testing.B) { benchmarkSChAlternating(100, b) }
func BenchmarkSChAlternating200(b *testing.B) { benchmarkSChAlternating(200, b) }
func BenchmarkSChAlternating300(b *testing.B) { benchmarkSChAlternating(300, b) }
func BenchmarkSChAlternating400(b *testing.B) { benchmarkSChAlternating(400, b) }
func BenchmarkSChAlternating500(b *testing.B) { benchmarkSChAlternating(500, b) }
func BenchmarkSChAlternating600(b *testing.B) { benchmarkSChAlternating(600, b) }
func BenchmarkSChAlternating700(b *testing.B) { benchmarkSChAlternating(700, b) }
func BenchmarkSChAlternating800(b *testing.B) { benchmarkSChAlternating(800, b) }
func BenchmarkSChAlternating900(b *testing.B) { benchmarkSChAlternating(900, b) }

func BenchmarkSChUnidirectional100(b *testing.B) { benchmarkSChUnidirectional(100, b) }
func BenchmarkSChUnidirectional200(b *testing.B) { benchmarkSChUnidirectional(200, b) }
func BenchmarkSChUnidirectional300(b *testing.B) { benchmarkSChUnidirectional(300, b) }
func BenchmarkSChUnidirectional400(b *testing.B) { benchmarkSChUnidirectional(400, b) }
func BenchmarkSChUnidirectional500(b *testing.B) { benchmarkSChUnidirectional(500, b) }
func BenchmarkSChUnidirectional600(b *testing.B) { benchmarkSChUnidirectional(600, b) }
func BenchmarkSChUnidirectional700(b *testing.B) { benchmarkSChUnidirectional(700, b) }
func BenchmarkSChUnidirectional800(b *testing.B) { benchmarkSChUnidirectional(800, b) }
func BenchmarkSChUnidirectional900(b *testing.B) { benchmarkSChUnidirectional(900, b) }
