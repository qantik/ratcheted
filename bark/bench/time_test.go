// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package main

import (
	"testing"

	"github.com/qantik/ratcheted/bark"
)

func alt(bark *bark.BARK, n int, b *testing.B) {
	alice, bob, _ := bark.Init()

	for i := 0; i < n/2; i++ {
		ka, ct, _ := bark.Send(alice)
		kb, _ := bark.Receive(bob, ct)
		_, _ = ka, kb

		ka, ct, _ = bark.Send(bob)
		kb, _ = bark.Receive(alice, ct)
		_, _ = ka, kb
	}
}

func deferredUni(bark *bark.BARK, n int, b *testing.B) {
	alice, bob, _ := bark.Init()

	var ks, cts [1000][]byte
	for i := 0; i < n/2; i++ {
		ka, ct, _ := bark.Send(alice)

		ks[i] = ka
		cts[i] = ct
	}

	for i := 0; i < n/2; i++ {
		ka, ct, _ := bark.Send(bob)
		kb, _ := bark.Receive(alice, ct)
		_, _ = ka, kb
	}

	for i := 0; i < n/2; i++ {
		kb, _ := bark.Receive(bob, cts[i])
		_ = kb
	}
}

func unidirectional(bark *bark.BARK, n int, b *testing.B) {
	alice, bob, _ := bark.Init()

	for i := 0; i < n/2; i++ {
		ka, ct, _ := bark.Send(alice)
		kb, _ := bark.Receive(bob, ct)
		_, _ = ka, kb
	}

	for i := 0; i < n/2; i++ {
		ka, ct, _ := bark.Send(bob)
		kb, _ := bark.Receive(alice, ct)
		_, _ = ka, kb
	}
}

func benchmarkAlt(bark *bark.BARK, i int, b *testing.B) {
	for n := 0; n < b.N; n++ {
		alt(bark, i, b)
	}
}

func benchmarkUni(bark *bark.BARK, i int, b *testing.B) {
	for n := 0; n < b.N; n++ {
		unidirectional(bark, i, b)
	}
}

func benchmarkDeferredUni(bark *bark.BARK, i int, b *testing.B) {
	for n := 0; n < b.N; n++ {
		deferredUni(bark, i, b)
	}
}

func BenchmarkAlt50(b *testing.B)  { benchmarkAlt(prt, 50, b) }
func BenchmarkAlt100(b *testing.B) { benchmarkAlt(prt, 100, b) }
func BenchmarkAlt200(b *testing.B) { benchmarkAlt(prt, 200, b) }
func BenchmarkAlt300(b *testing.B) { benchmarkAlt(prt, 300, b) }
func BenchmarkAlt400(b *testing.B) { benchmarkAlt(prt, 400, b) }
func BenchmarkAlt500(b *testing.B) { benchmarkAlt(prt, 500, b) }
func BenchmarkAlt600(b *testing.B) { benchmarkAlt(prt, 600, b) }
func BenchmarkAlt700(b *testing.B) { benchmarkAlt(prt, 700, b) }
func BenchmarkAlt800(b *testing.B) { benchmarkAlt(prt, 800, b) }
func BenchmarkAlt900(b *testing.B) { benchmarkAlt(prt, 900, b) }

func BenchmarkUni50(b *testing.B)  { benchmarkUni(prt, 50, b) }
func BenchmarkUni100(b *testing.B) { benchmarkUni(prt, 100, b) }
func BenchmarkUni200(b *testing.B) { benchmarkUni(prt, 200, b) }
func BenchmarkUni300(b *testing.B) { benchmarkUni(prt, 300, b) }
func BenchmarkUni400(b *testing.B) { benchmarkUni(prt, 400, b) }
func BenchmarkUni500(b *testing.B) { benchmarkUni(prt, 500, b) }
func BenchmarkUni600(b *testing.B) { benchmarkUni(prt, 600, b) }
func BenchmarkUni700(b *testing.B) { benchmarkUni(prt, 700, b) }
func BenchmarkUni800(b *testing.B) { benchmarkUni(prt, 800, b) }
func BenchmarkUni900(b *testing.B) { benchmarkUni(prt, 900, b) }

func BenchmarkDeferredUni50(b *testing.B)  { benchmarkDeferredUni(prt, 50, b) }
func BenchmarkDeferredUni100(b *testing.B) { benchmarkDeferredUni(prt, 100, b) }
func BenchmarkDeferredUni200(b *testing.B) { benchmarkDeferredUni(prt, 200, b) }
func BenchmarkDeferredUni300(b *testing.B) { benchmarkDeferredUni(prt, 300, b) }
func BenchmarkDeferredUni400(b *testing.B) { benchmarkDeferredUni(prt, 400, b) }
func BenchmarkDeferredUni500(b *testing.B) { benchmarkDeferredUni(prt, 500, b) }
func BenchmarkDeferredUni600(b *testing.B) { benchmarkDeferredUni(prt, 600, b) }
func BenchmarkDeferredUni700(b *testing.B) { benchmarkDeferredUni(prt, 700, b) }
func BenchmarkDeferredUni800(b *testing.B) { benchmarkDeferredUni(prt, 800, b) }
func BenchmarkDeferredUni900(b *testing.B) { benchmarkDeferredUni(prt, 900, b) }
