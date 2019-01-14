// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package main

import (
	"testing"

	"github.com/qantik/ratcheted/acd"
)

func alt(dr *acd.DoubleRatchet, n int) {
	alice, bob, _ := dr.Init()

	for i := 0; i < n/2; i++ {
		ct, _ := dr.Send(alice, msg)
		pt, _ := dr.Receive(bob, ct)
		_ = pt

		ct, _ = dr.Send(bob, msg)
		pt, _ = dr.Receive(alice, ct)
		_ = pt
	}
}

func uni(dr *acd.DoubleRatchet, n int) {
	alice, bob, _ := dr.Init()

	for i := 0; i < n/2; i++ {
		ct, _ := dr.Send(alice, msg)
		pt, _ := dr.Receive(bob, ct)
		_ = pt
	}

	for i := 0; i < n/2; i++ {
		ct, _ := dr.Send(bob, msg)
		pt, _ := dr.Receive(alice, ct)
		_ = pt
	}
}

func deferredUni(dr *acd.DoubleRatchet, n int) {
	alice, bob, _ := dr.Init()

	var cts [1000][]byte
	for i := 0; i < n/2; i++ {
		ct, _ := dr.Send(alice, msg)
		cts[i] = ct
	}

	for i := 0; i < n/2; i++ {
		ct, _ := dr.Send(bob, msg)
		pt, _ := dr.Receive(alice, ct)
		_ = pt
	}

	for i := 0; i < n/2; i++ {
		pt, _ := dr.Receive(bob, cts[i])
		_ = pt
	}
}

func benchmarkAlt(dr *acd.DoubleRatchet, i int, b *testing.B) {
	for n := 0; n < b.N; n++ {
		alt(dr, i)
	}
}

func benchmarkUni(dr *acd.DoubleRatchet, i int, b *testing.B) {
	for n := 0; n < b.N; n++ {
		uni(dr, i)
	}
}

func benchmarkDeferredUni(dr *acd.DoubleRatchet, i int, b *testing.B) {
	for n := 0; n < b.N; n++ {
		deferredUni(dr, i)
	}
}

func BenchmarkAlt50(b *testing.B)  { benchmarkAlt(dr, 50, b) }
func BenchmarkAlt100(b *testing.B) { benchmarkAlt(dr, 100, b) }
func BenchmarkAlt200(b *testing.B) { benchmarkAlt(dr, 200, b) }
func BenchmarkAlt300(b *testing.B) { benchmarkAlt(dr, 300, b) }
func BenchmarkAlt400(b *testing.B) { benchmarkAlt(dr, 400, b) }
func BenchmarkAlt500(b *testing.B) { benchmarkAlt(dr, 500, b) }
func BenchmarkAlt600(b *testing.B) { benchmarkAlt(dr, 600, b) }
func BenchmarkAlt700(b *testing.B) { benchmarkAlt(dr, 700, b) }
func BenchmarkAlt800(b *testing.B) { benchmarkAlt(dr, 800, b) }
func BenchmarkAlt900(b *testing.B) { benchmarkAlt(dr, 900, b) }

func BenchmarkUni50(b *testing.B)  { benchmarkUni(dr, 50, b) }
func BenchmarkUni100(b *testing.B) { benchmarkUni(dr, 100, b) }
func BenchmarkUni200(b *testing.B) { benchmarkUni(dr, 200, b) }
func BenchmarkUni300(b *testing.B) { benchmarkUni(dr, 300, b) }
func BenchmarkUni400(b *testing.B) { benchmarkUni(dr, 400, b) }
func BenchmarkUni500(b *testing.B) { benchmarkUni(dr, 500, b) }
func BenchmarkUni600(b *testing.B) { benchmarkUni(dr, 600, b) }
func BenchmarkUni700(b *testing.B) { benchmarkUni(dr, 700, b) }
func BenchmarkUni800(b *testing.B) { benchmarkUni(dr, 800, b) }
func BenchmarkUni900(b *testing.B) { benchmarkUni(dr, 900, b) }

func BenchmarkDeferredUni50(b *testing.B)  { benchmarkDeferredUni(dr, 50, b) }
func BenchmarkDeferredUni100(b *testing.B) { benchmarkDeferredUni(dr, 100, b) }
func BenchmarkDeferredUni200(b *testing.B) { benchmarkDeferredUni(dr, 200, b) }
func BenchmarkDeferredUni300(b *testing.B) { benchmarkDeferredUni(dr, 300, b) }
func BenchmarkDeferredUni400(b *testing.B) { benchmarkDeferredUni(dr, 400, b) }
func BenchmarkDeferredUni500(b *testing.B) { benchmarkDeferredUni(dr, 500, b) }
func BenchmarkDeferredUni600(b *testing.B) { benchmarkDeferredUni(dr, 600, b) }
func BenchmarkDeferredUni700(b *testing.B) { benchmarkDeferredUni(dr, 700, b) }
func BenchmarkDeferredUni800(b *testing.B) { benchmarkDeferredUni(dr, 800, b) }
func BenchmarkDeferredUni900(b *testing.B) { benchmarkDeferredUni(dr, 900, b) }
