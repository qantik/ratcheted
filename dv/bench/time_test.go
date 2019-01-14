// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package main

import (
	"testing"

	"github.com/qantik/ratcheted/dv"
)

func alt(bark *dv.BARK, n int) {
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

func deferredUni(bark *dv.BARK, n int) {
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

func unidirectional(bark *dv.BARK, n int) {
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

func benchmarkAlt(bark *dv.BARK, i int, b *testing.B) {
	for n := 0; n < b.N; n++ {
		alt(bark, i)
	}
}

func benchmarkUni(bark *dv.BARK, i int, b *testing.B) {
	for n := 0; n < b.N; n++ {
		unidirectional(bark, i)
	}
}

func benchmarkDeferredUni(bark *dv.BARK, i int, b *testing.B) {
	for n := 0; n < b.N; n++ {
		deferredUni(bark, i)
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

func BenchmarkUni50(b *testing.B)  { benchmarkUni(bark, 50, b) }
func BenchmarkUni100(b *testing.B) { benchmarkUni(bark, 100, b) }
func BenchmarkUni200(b *testing.B) { benchmarkUni(bark, 200, b) }
func BenchmarkUni300(b *testing.B) { benchmarkUni(bark, 300, b) }
func BenchmarkUni400(b *testing.B) { benchmarkUni(bark, 400, b) }
func BenchmarkUni500(b *testing.B) { benchmarkUni(bark, 500, b) }
func BenchmarkUni600(b *testing.B) { benchmarkUni(bark, 600, b) }
func BenchmarkUni700(b *testing.B) { benchmarkUni(bark, 700, b) }
func BenchmarkUni800(b *testing.B) { benchmarkUni(bark, 800, b) }
func BenchmarkUni900(b *testing.B) { benchmarkUni(bark, 900, b) }

func BenchmarkDeferredUni50(b *testing.B)  { benchmarkDeferredUni(bark, 50, b) }
func BenchmarkDeferredUni100(b *testing.B) { benchmarkDeferredUni(bark, 100, b) }
func BenchmarkDeferredUni200(b *testing.B) { benchmarkDeferredUni(bark, 200, b) }
func BenchmarkDeferredUni300(b *testing.B) { benchmarkDeferredUni(bark, 300, b) }
func BenchmarkDeferredUni400(b *testing.B) { benchmarkDeferredUni(bark, 400, b) }
func BenchmarkDeferredUni500(b *testing.B) { benchmarkDeferredUni(bark, 500, b) }
func BenchmarkDeferredUni600(b *testing.B) { benchmarkDeferredUni(bark, 600, b) }
func BenchmarkDeferredUni700(b *testing.B) { benchmarkDeferredUni(bark, 700, b) }
func BenchmarkDeferredUni800(b *testing.B) { benchmarkDeferredUni(bark, 800, b) }
func BenchmarkDeferredUni900(b *testing.B) { benchmarkDeferredUni(bark, 900, b) }
