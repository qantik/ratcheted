// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package main

import (
	"fmt"
	"testing"

	"github.com/qantik/ratcheted/dv"
)

func time_alt(p dv.Protocol, n int) {
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

func time_uni(p dv.Protocol, n int) {
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

func time_def(p dv.Protocol, n int) {
	alice, bob, _ := p.Init()

	var cts [100000][]byte
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

func time_hybrid(p dv.Protocol, tp func(p dv.Protocol, i int)) {
	s := ""
	for i := 10000; i <= 1e5; i += 10000 {
		fn := func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				tp(p, i)
			}
		}
		res := testing.Benchmark(fn)

		s += fmt.Sprintf("(%d,%.4f)", i, float64(res.T)/1000000000.0/float64(res.N))
		fmt.Println(s)
	}
	fmt.Println(s)
}
