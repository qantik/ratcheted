// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package main

import (
	"fmt"
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
	alice, bob, _ := p.Init()

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
	alice, bob, _ := p.Init()

	var cts [1200][]byte
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

// func benchmarkAlt(p dv.Protocol, i int, b *testing.B) {
// 	for n := 0; n < b.N; n++ {
// 		alt(p, i)
// 	}
// }

// func benchmarkUni(arcad dv.Protocol, i int, b *testing.B) {
// 	for n := 0; n < b.N; n++ {
// 		unidirectional(arcad, i)
// 	}
// }

// func benchmarkDeferredUni(arcad dv.Protocol, i int, b *testing.B) {
// 	for n := 0; n < b.N; n++ {
// 		deferredUni(arcad, i)
// 	}
// }

func time(p dv.Protocol, tp func(p dv.Protocol, i int)) {
	s := ""
	for _, i := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100, 1200} {
		fn := func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				tp(p, i)
			}
		}
		res := testing.Benchmark(fn)

		s += fmt.Sprintf("(%d,%.4f)", i, float64(res.T)/1000000000.0/float64(res.N))
	}
	fmt.Println(s)
}

//func main() {
//	//bench(arcad, alt)
//	// benchAlt(arcad)
//	// benchAlt(arcad)

//	msg := make([]int, 10)

//	s := ""
//	for i, n := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900} {
//		msg[i], _ = size_alternating(lite, n)
//		s += fmt.Sprintf("(%d,%.2f)", n, float32(msg[i])/1000)
//	}
//	fmt.Println("Total Message Size (ALT)\n", s)

//	s = ""
//	for i, n := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900} {
//		msg[i], _ = size_unidirectional(lite, n)
//		s += fmt.Sprintf("(%d,%.2f)", n, float32(msg[i])/1000)
//	}
//	fmt.Println("Total Message Size (UNI)\n", s)

//	s = ""
//	for i, n := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900} {
//		msg[i], _ = size_def(lite, n)
//		s += fmt.Sprintf("(%d,%.2f)", n, float32(msg[i])/1000)
//	}
//	fmt.Println("Total Message Size (DEF)\n", s)

//}

// func BenchmarkAlt50(b *testing.B)   { benchmarkAlt(arcad, 50, b) }
// func BenchmarkAlt100(b *testing.B)  { benchmarkAlt(arcad, 100, b) }
// func BenchmarkAlt200(b *testing.B)  { benchmarkAlt(arcad, 200, b) }
// func BenchmarkAlt300(b *testing.B)  { benchmarkAlt(arcad, 300, b) }
// func BenchmarkAlt400(b *testing.B)  { benchmarkAlt(arcad, 400, b) }
// func BenchmarkAlt500(b *testing.B)  { benchmarkAlt(arcad, 500, b) }
// func BenchmarkAlt600(b *testing.B)  { benchmarkAlt(arcad, 600, b) }
// func BenchmarkAlt700(b *testing.B)  { benchmarkAlt(arcad, 700, b) }
// func BenchmarkAlt800(b *testing.B)  { benchmarkAlt(arcad, 800, b) }
// func BenchmarkAlt900(b *testing.B)  { benchmarkAlt(arcad, 900, b) }
// func BenchmarkAlt1000(b *testing.B) { benchmarkAlt(arcad, 1000, b) }
// func BenchmarkAlt1100(b *testing.B) { benchmarkAlt(arcad, 1100, b) }
// func BenchmarkAlt1200(b *testing.B) { benchmarkAlt(arcad, 1200, b) }

// func BenchmarkUni50(b *testing.B)   { benchmarkUni(arcad, 50, b) }
// func BenchmarkUni100(b *testing.B)  { benchmarkUni(arcad, 100, b) }
// func BenchmarkUni200(b *testing.B)  { benchmarkUni(arcad, 200, b) }
// func BenchmarkUni300(b *testing.B)  { benchmarkUni(arcad, 300, b) }
// func BenchmarkUni400(b *testing.B)  { benchmarkUni(arcad, 400, b) }
// func BenchmarkUni500(b *testing.B)  { benchmarkUni(arcad, 500, b) }
// func BenchmarkUni600(b *testing.B)  { benchmarkUni(arcad, 600, b) }
// func BenchmarkUni700(b *testing.B)  { benchmarkUni(arcad, 700, b) }
// func BenchmarkUni800(b *testing.B)  { benchmarkUni(arcad, 800, b) }
// func BenchmarkUni900(b *testing.B)  { benchmarkUni(arcad, 900, b) }
// func BenchmarkUni1000(b *testing.B) { benchmarkUni(arcad, 1000, b) }
// func BenchmarkUni1100(b *testing.B) { benchmarkUni(arcad, 1100, b) }
// func BenchmarkUni1200(b *testing.B) { benchmarkUni(arcad, 1200, b) }

// func BenchmarkDeferredUni50(b *testing.B)   { benchmarkDeferredUni(arcad, 50, b) }
// func BenchmarkDeferredUni100(b *testing.B)  { benchmarkDeferredUni(arcad, 100, b) }
// func BenchmarkDeferredUni200(b *testing.B)  { benchmarkDeferredUni(arcad, 200, b) }
// func BenchmarkDeferredUni300(b *testing.B)  { benchmarkDeferredUni(arcad, 300, b) }
// func BenchmarkDeferredUni400(b *testing.B)  { benchmarkDeferredUni(arcad, 400, b) }
// func BenchmarkDeferredUni500(b *testing.B)  { benchmarkDeferredUni(arcad, 500, b) }
// func BenchmarkDeferredUni600(b *testing.B)  { benchmarkDeferredUni(arcad, 600, b) }
// func BenchmarkDeferredUni700(b *testing.B)  { benchmarkDeferredUni(arcad, 700, b) }
// func BenchmarkDeferredUni800(b *testing.B)  { benchmarkDeferredUni(arcad, 800, b) }
// func BenchmarkDeferredUni900(b *testing.B)  { benchmarkDeferredUni(arcad, 900, b) }
// func BenchmarkDeferredUni1000(b *testing.B) { benchmarkDeferredUni(arcad, 1000, b) }
// func BenchmarkDeferredUni1100(b *testing.B) { benchmarkDeferredUni(arcad, 1100, b) }
// func BenchmarkDeferredUni1200(b *testing.B) { benchmarkDeferredUni(arcad, 1200, b) }

// func BenchmarkHybridAlt50(b *testing.B)   { benchmarkAlt(hybrid, 50, b) }
// func BenchmarkHybridAlt100(b *testing.B)  { benchmarkAlt(hybrid, 100, b) }
// func BenchmarkHybridAlt200(b *testing.B)  { benchmarkAlt(hybrid, 200, b) }
// func BenchmarkHybridAlt300(b *testing.B)  { benchmarkAlt(hybrid, 300, b) }
// func BenchmarkHybridAlt400(b *testing.B)  { benchmarkAlt(hybrid, 400, b) }
// func BenchmarkHybridAlt500(b *testing.B)  { benchmarkAlt(hybrid, 500, b) }
// func BenchmarkHybridAlt600(b *testing.B)  { benchmarkAlt(hybrid, 600, b) }
// func BenchmarkHybridAlt700(b *testing.B)  { benchmarkAlt(hybrid, 700, b) }
// func BenchmarkHybridAlt800(b *testing.B)  { benchmarkAlt(hybrid, 800, b) }
// func BenchmarkHybridAlt900(b *testing.B)  { benchmarkAlt(hybrid, 900, b) }
// func BenchmarkHybridAlt1000(b *testing.B) { benchmarkAlt(hybrid, 1000, b) }
// func BenchmarkHybridAlt1100(b *testing.B) { benchmarkAlt(hybrid, 1100, b) }
// func BenchmarkHybridAlt1200(b *testing.B) { benchmarkAlt(hybrid, 1200, b) }

// func BenchmarkHybridUni50(b *testing.B)   { benchmarkUni(hybrid, 50, b) }
// func BenchmarkHybridUni100(b *testing.B)  { benchmarkUni(hybrid, 100, b) }
// func BenchmarkHybridUni200(b *testing.B)  { benchmarkUni(hybrid, 200, b) }
// func BenchmarkHybridUni300(b *testing.B)  { benchmarkUni(hybrid, 300, b) }
// func BenchmarkHybridUni400(b *testing.B)  { benchmarkUni(hybrid, 400, b) }
// func BenchmarkHybridUni500(b *testing.B)  { benchmarkUni(hybrid, 500, b) }
// func BenchmarkHybridUni600(b *testing.B)  { benchmarkUni(hybrid, 600, b) }
// func BenchmarkHybridUni700(b *testing.B)  { benchmarkUni(hybrid, 700, b) }
// func BenchmarkHybridUni800(b *testing.B)  { benchmarkUni(hybrid, 800, b) }
// func BenchmarkHybridUni900(b *testing.B)  { benchmarkUni(hybrid, 900, b) }
// func BenchmarkHybridUni1000(b *testing.B) { benchmarkUni(hybrid, 1000, b) }
// func BenchmarkHybridUni1100(b *testing.B) { benchmarkUni(hybrid, 1100, b) }
// func BenchmarkHybridUni1200(b *testing.B) { benchmarkUni(hybrid, 1200, b) }

// func BenchmarkHybridDef50(b *testing.B)   { benchmarkDeferredUni(hybrid, 50, b) }
// func BenchmarkHybridDef100(b *testing.B)  { benchmarkDeferredUni(hybrid, 100, b) }
// func BenchmarkHybridDef200(b *testing.B)  { benchmarkDeferredUni(hybrid, 200, b) }
// func BenchmarkHybridDef300(b *testing.B)  { benchmarkDeferredUni(hybrid, 300, b) }
// func BenchmarkHybridDef400(b *testing.B)  { benchmarkDeferredUni(hybrid, 400, b) }
// func BenchmarkHybridDef500(b *testing.B)  { benchmarkDeferredUni(hybrid, 500, b) }
// func BenchmarkHybridDef600(b *testing.B)  { benchmarkDeferredUni(hybrid, 600, b) }
// func BenchmarkHybridDef700(b *testing.B)  { benchmarkDeferredUni(hybrid, 700, b) }
// func BenchmarkHybridDef800(b *testing.B)  { benchmarkDeferredUni(hybrid, 800, b) }
// func BenchmarkHybridDef900(b *testing.B)  { benchmarkDeferredUni(hybrid, 900, b) }
// func BenchmarkHybridDef1000(b *testing.B) { benchmarkDeferredUni(hybrid, 1000, b) }
// func BenchmarkHybridDef1100(b *testing.B) { benchmarkDeferredUni(hybrid, 1100, b) }
// func BenchmarkHybridDef1200(b *testing.B) { benchmarkDeferredUni(hybrid, 1200, b) }

// func BenchmarkBlockchainAlt50(b *testing.B)   { benchmarkAlt(block, 50, b) }
// func BenchmarkBlockchainAlt100(b *testing.B)  { benchmarkAlt(block, 100, b) }
// func BenchmarkBlockchainAlt200(b *testing.B)  { benchmarkAlt(block, 200, b) }
// func BenchmarkBlockchainAlt300(b *testing.B)  { benchmarkAlt(block, 300, b) }
// func BenchmarkBlockchainAlt400(b *testing.B)  { benchmarkAlt(block, 400, b) }
// func BenchmarkBlockchainAlt500(b *testing.B)  { benchmarkAlt(block, 500, b) }
// func BenchmarkBlockchainAlt600(b *testing.B)  { benchmarkAlt(block, 600, b) }
// func BenchmarkBlockchainAlt700(b *testing.B)  { benchmarkAlt(block, 700, b) }
// func BenchmarkBlockchainAlt800(b *testing.B)  { benchmarkAlt(block, 800, b) }
// func BenchmarkBlockchainAlt900(b *testing.B)  { benchmarkAlt(block, 900, b) }
// func BenchmarkBlockchainAlt1000(b *testing.B) { benchmarkAlt(block, 1000, b) }
// func BenchmarkBlockchainAlt1100(b *testing.B) { benchmarkAlt(block, 1100, b) }
// func BenchmarkBlockchainAlt1200(b *testing.B) { benchmarkAlt(block, 1200, b) }

// func BenchmarkBlockchainUni50(b *testing.B)   { benchmarkUni(block, 50, b) }
// func BenchmarkBlockchainUni100(b *testing.B)  { benchmarkUni(block, 100, b) }
// func BenchmarkBlockchainUni200(b *testing.B)  { benchmarkUni(block, 200, b) }
// func BenchmarkBlockchainUni300(b *testing.B)  { benchmarkUni(block, 300, b) }
// func BenchmarkBlockchainUni400(b *testing.B)  { benchmarkUni(block, 400, b) }
// func BenchmarkBlockchainUni500(b *testing.B)  { benchmarkUni(block, 500, b) }
// func BenchmarkBlockchainUni600(b *testing.B)  { benchmarkUni(block, 600, b) }
// func BenchmarkBlockchainUni700(b *testing.B)  { benchmarkUni(block, 700, b) }
// func BenchmarkBlockchainUni800(b *testing.B)  { benchmarkUni(block, 800, b) }
// func BenchmarkBlockchainUni900(b *testing.B)  { benchmarkUni(block, 900, b) }
// func BenchmarkBlockchainUni1000(b *testing.B) { benchmarkUni(block, 1000, b) }
// func BenchmarkBlockchainUni1100(b *testing.B) { benchmarkUni(block, 1100, b) }
// func BenchmarkBlockchainUni1200(b *testing.B) { benchmarkUni(block, 1200, b) }

// func BenchmarkBlockchainDef50(b *testing.B)   { benchmarkDeferredUni(block, 50, b) }
// func BenchmarkBlockchainDef100(b *testing.B)  { benchmarkDeferredUni(block, 100, b) }
// func BenchmarkBlockchainDef200(b *testing.B)  { benchmarkDeferredUni(block, 200, b) }
// func BenchmarkBlockchainDef300(b *testing.B)  { benchmarkDeferredUni(block, 300, b) }
// func BenchmarkBlockchainDef400(b *testing.B)  { benchmarkDeferredUni(block, 400, b) }
// func BenchmarkBlockchainDef500(b *testing.B)  { benchmarkDeferredUni(block, 500, b) }
// func BenchmarkBlockchainDef600(b *testing.B)  { benchmarkDeferredUni(block, 600, b) }
// func BenchmarkBlockchainDef700(b *testing.B)  { benchmarkDeferredUni(block, 700, b) }
// func BenchmarkBlockchainDef800(b *testing.B)  { benchmarkDeferredUni(block, 800, b) }
// func BenchmarkBlockchainDef900(b *testing.B)  { benchmarkDeferredUni(block, 900, b) }
// func BenchmarkBlockchainDef1000(b *testing.B) { benchmarkDeferredUni(block, 1000, b) }
// func BenchmarkBlockchainDef1100(b *testing.B) { benchmarkDeferredUni(block, 1100, b) }
// func BenchmarkBlockchainDef1200(b *testing.B) { benchmarkDeferredUni(block, 1200, b) }
