// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package main

import (
	"testing"

	"github.com/qantik/ratcheted/dv"
)

func alt(p dv.Protocol, n int) {
	alice, bob, _ := p.Init()

	for i := 0; i < n/2; i++ {
		ct, _ := p.Send(alice, ad, msg)
		pt, _ := p.Receive(bob, ad, ct)
		_ = pt

		ct, _ = p.Send(bob, ad, msg)
		pt, _ = p.Receive(alice, ad, ct)
		_ = pt
	}
}

func unidirectional(p dv.Protocol, n int) {
	alice, bob, _ := arcad.Init()

	for i := 0; i < n/2; i++ {
		ct, _ := p.Send(alice, ad, msg)
		pt, _ := p.Receive(bob, ad, ct)
		_ = pt
	}

	for i := 0; i < n/2; i++ {
		ct, _ := p.Send(bob, ad, msg)
		pt, _ := p.Receive(alice, ad, ct)
		_ = pt
	}
}

func deferredUni(p dv.Protocol, n int) {
	alice, bob, _ := arcad.Init()

	var cts [1000][]byte
	for i := 0; i < n/2; i++ {
		ct, _ := p.Send(alice, ad, msg)

		cts[i] = ct
	}

	for i := 0; i < n/2; i++ {
		ct, _ := p.Send(bob, ad, msg)
		pt, _ := p.Receive(alice, ad, ct)
		_ = pt
	}

	for i := 0; i < n/2; i++ {
		pt, _ := p.Receive(bob, ad, cts[i])
		_ = pt
	}
}

func assoc(n int) []byte {
	var add []byte
	if n == 250 || n == 500 || n == 750 || n == 1000 {
		add = append([]byte{byte(1)}, ad...)
	} else {
		add = append([]byte{byte(0)}, ad...)
	}
	return add
}

func hybridAlt(n int) {
	alice, bob, _ := hybrid.Init()

	inc := 0

	for i := 1; i <= n/2; i++ {
		ct, _ := hybrid.Send(alice, assoc(inc), msg)
		pt, _ := hybrid.Receive(bob, assoc(inc), ct)
		_ = pt
		inc++

		ct, _ = hybrid.Send(bob, assoc(inc), msg)
		pt, _ = hybrid.Receive(alice, assoc(inc), ct)
		_ = pt
		inc++
	}
}

func benchmarkAlt(p dv.Protocol, i int, b *testing.B) {
	for n := 0; n < b.N; n++ {
		alt(p, i)
	}
}

func benchmarkUni(arcad dv.Protocol, i int, b *testing.B) {
	for n := 0; n < b.N; n++ {
		unidirectional(arcad, i)
	}
}

func benchmarkDeferredUni(arcad dv.Protocol, i int, b *testing.B) {
	for n := 0; n < b.N; n++ {
		deferredUni(arcad, i)
	}
}

func BenchmarkAlt50(b *testing.B)  { benchmarkAlt(lite, 50, b) }
func BenchmarkAlt100(b *testing.B) { benchmarkAlt(lite, 100, b) }
func BenchmarkAlt200(b *testing.B) { benchmarkAlt(lite, 200, b) }
func BenchmarkAlt300(b *testing.B) { benchmarkAlt(lite, 300, b) }
func BenchmarkAlt400(b *testing.B) { benchmarkAlt(lite, 400, b) }
func BenchmarkAlt500(b *testing.B) { benchmarkAlt(lite, 500, b) }
func BenchmarkAlt600(b *testing.B) { benchmarkAlt(lite, 600, b) }
func BenchmarkAlt700(b *testing.B) { benchmarkAlt(lite, 700, b) }
func BenchmarkAlt800(b *testing.B) { benchmarkAlt(lite, 800, b) }
func BenchmarkAlt900(b *testing.B) { benchmarkAlt(lite, 900, b) }

func BenchmarkUni50(b *testing.B)  { benchmarkUni(arcad, 50, b) }
func BenchmarkUni100(b *testing.B) { benchmarkUni(arcad, 100, b) }
func BenchmarkUni200(b *testing.B) { benchmarkUni(arcad, 200, b) }
func BenchmarkUni300(b *testing.B) { benchmarkUni(arcad, 300, b) }
func BenchmarkUni400(b *testing.B) { benchmarkUni(arcad, 400, b) }
func BenchmarkUni500(b *testing.B) { benchmarkUni(arcad, 500, b) }
func BenchmarkUni600(b *testing.B) { benchmarkUni(arcad, 600, b) }
func BenchmarkUni700(b *testing.B) { benchmarkUni(arcad, 700, b) }
func BenchmarkUni800(b *testing.B) { benchmarkUni(arcad, 800, b) }
func BenchmarkUni900(b *testing.B) { benchmarkUni(arcad, 900, b) }

func BenchmarkDeferredUni50(b *testing.B)  { benchmarkDeferredUni(arcad, 50, b) }
func BenchmarkDeferredUni100(b *testing.B) { benchmarkDeferredUni(arcad, 100, b) }
func BenchmarkDeferredUni200(b *testing.B) { benchmarkDeferredUni(arcad, 200, b) }
func BenchmarkDeferredUni300(b *testing.B) { benchmarkDeferredUni(arcad, 300, b) }
func BenchmarkDeferredUni400(b *testing.B) { benchmarkDeferredUni(arcad, 400, b) }
func BenchmarkDeferredUni500(b *testing.B) { benchmarkDeferredUni(arcad, 500, b) }
func BenchmarkDeferredUni600(b *testing.B) { benchmarkDeferredUni(arcad, 600, b) }
func BenchmarkDeferredUni700(b *testing.B) { benchmarkDeferredUni(arcad, 700, b) }
func BenchmarkDeferredUni800(b *testing.B) { benchmarkDeferredUni(arcad, 800, b) }
func BenchmarkDeferredUni900(b *testing.B) { benchmarkDeferredUni(arcad, 900, b) }

func BenchmarkHybridAlt50(b *testing.B)   { benchmarkAlt(hybrid, 50, b) }
func BenchmarkHybridAlt100(b *testing.B)  { benchmarkAlt(hybrid, 100, b) }
func BenchmarkHybridAlt200(b *testing.B)  { benchmarkAlt(hybrid, 200, b) }
func BenchmarkHybridAlt300(b *testing.B)  { benchmarkAlt(hybrid, 300, b) }
func BenchmarkHybridAlt400(b *testing.B)  { benchmarkAlt(hybrid, 400, b) }
func BenchmarkHybridAlt500(b *testing.B)  { benchmarkAlt(hybrid, 500, b) }
func BenchmarkHybridAlt600(b *testing.B)  { benchmarkAlt(hybrid, 600, b) }
func BenchmarkHybridAlt700(b *testing.B)  { benchmarkAlt(hybrid, 700, b) }
func BenchmarkHybridAlt800(b *testing.B)  { benchmarkAlt(hybrid, 800, b) }
func BenchmarkHybridAlt900(b *testing.B)  { benchmarkAlt(hybrid, 900, b) }
func BenchmarkHybridAlt1000(b *testing.B) { benchmarkAlt(hybrid, 1000, b) }
func BenchmarkHybridAlt1100(b *testing.B) { benchmarkAlt(hybrid, 1100, b) }
func BenchmarkHybridAlt1200(b *testing.B) { benchmarkAlt(hybrid, 1200, b) }
