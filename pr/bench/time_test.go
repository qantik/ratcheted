// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package main

import (
	"testing"
)

func alt(n int, b *testing.B) {
	alice, bob, _ := brke.Init()

	for i := 0; i < n/2; i++ {
		ka, c, _ := brke.Send(alice, ad)
		kb, _ := brke.Receive(bob, ad, c)
		_, _ = ka, kb

		kb, c, _ = brke.Send(bob, ad)
		ka, _ = brke.Receive(alice, ad, c)
		_, _ = ka, kb
	}
}

func uni(n int, b *testing.B) {
	alice, bob, _ := brke.Init()

	for i := 0; i < n/2; i++ {
		ka, c, _ := brke.Send(alice, ad)
		kb, _ := brke.Receive(bob, ad, c)
		_, _ = ka, kb
	}

	for i := 0; i < n/2; i++ {
		kb, c, _ := brke.Send(bob, ad)
		ka, _ := brke.Receive(alice, ad, c)
		_, _ = ka, kb
	}
}

func deferredUni(n int, b *testing.B) {
	alice, bob, _ := brke.Init()

	var ks [1000][]byte
	var cs [1000][][]byte
	for i := 0; i < n/2; i++ {
		k, c, _ := brke.Send(alice, ad)
		ks[i] = k
		cs[i] = c
	}

	for i := 0; i < n/2; i++ {
		kb, c, _ := brke.Send(bob, ad)
		ka, _ := brke.Receive(alice, ad, c)
		_, _ = ka, kb
	}

	for i := 0; i < n/2; i++ {
		k, _ := brke.Receive(bob, ad, cs[i])
		_ = k
	}
}

func benchmarkAlt(i int, b *testing.B) {
	for n := 0; n < b.N; n++ {
		alt(i, b)
	}
}

func benchmarkDeferredUni(i int, b *testing.B) {
	for n := 0; n < b.N; n++ {
		deferredUni(i, b)
	}
}

func benchmarkUni(i int, b *testing.B) {
	for n := 0; n < b.N; n++ {
		uni(i, b)
	}
}

func BenchmarkAlt50(b *testing.B)  { benchmarkAlt(50, b) }
func BenchmarkAlt100(b *testing.B) { benchmarkAlt(100, b) }
func BenchmarkAlt200(b *testing.B) { benchmarkAlt(200, b) }
func BenchmarkAlt300(b *testing.B) { benchmarkAlt(300, b) }
func BenchmarkAlt400(b *testing.B) { benchmarkAlt(400, b) }
func BenchmarkAlt500(b *testing.B) { benchmarkAlt(500, b) }
func BenchmarkAlt600(b *testing.B) { benchmarkAlt(600, b) }
func BenchmarkAlt700(b *testing.B) { benchmarkAlt(700, b) }
func BenchmarkAlt800(b *testing.B) { benchmarkAlt(800, b) }
func BenchmarkAlt900(b *testing.B) { benchmarkAlt(900, b) }

func BenchmarkDeferredUni50(b *testing.B)  { benchmarkDeferredUni(50, b) }
func BenchmarkDeferredUni100(b *testing.B) { benchmarkDeferredUni(100, b) }
func BenchmarkDeferredUni200(b *testing.B) { benchmarkDeferredUni(200, b) }
func BenchmarkDeferredUni300(b *testing.B) { benchmarkDeferredUni(300, b) }
func BenchmarkDeferredUni400(b *testing.B) { benchmarkDeferredUni(400, b) }
func BenchmarkDeferredUni500(b *testing.B) { benchmarkDeferredUni(500, b) }
func BenchmarkDeferredUni600(b *testing.B) { benchmarkDeferredUni(600, b) }
func BenchmarkDeferredUni700(b *testing.B) { benchmarkDeferredUni(700, b) }
func BenchmarkDeferredUni800(b *testing.B) { benchmarkDeferredUni(800, b) }
func BenchmarkDeferredUni900(b *testing.B) { benchmarkDeferredUni(900, b) }

func BenchmarkUni50(b *testing.B)  { benchmarkUni(50, b) }
func BenchmarkUni100(b *testing.B) { benchmarkUni(100, b) }
func BenchmarkUni200(b *testing.B) { benchmarkUni(200, b) }
func BenchmarkUni300(b *testing.B) { benchmarkUni(300, b) }
func BenchmarkUni400(b *testing.B) { benchmarkUni(400, b) }
func BenchmarkUni500(b *testing.B) { benchmarkUni(500, b) }
func BenchmarkUni600(b *testing.B) { benchmarkUni(600, b) }
func BenchmarkUni700(b *testing.B) { benchmarkUni(700, b) }
func BenchmarkUni800(b *testing.B) { benchmarkUni(800, b) }
func BenchmarkUni900(b *testing.B) { benchmarkUni(900, b) }
