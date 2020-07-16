// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package main

import (
	"fmt"

	"github.com/qantik/ratcheted/dv"
)

func size_alt(p dv.Protocol, n int) (int, int) {
	alice, bob, _ := p.Init()

	msgSize := 0
	maxState := 0

	for i := 0; i < n/2; i++ {
		ct, _ := p.Send(alice, ad, msg)
		pt, _ := p.Receive(bob, ad, ct)
		_ = pt

		msgSize += len(ct)
		maxState = max(maxState, alice.Size())
		maxState = max(maxState, bob.Size())

		ct, _ = p.Send(bob, ad, msg)
		pt, _ = p.Receive(alice, ad, ct)
		_ = pt

		msgSize += len(ct)
		maxState = max(maxState, alice.Size())
		maxState = max(maxState, bob.Size())
	}

	return msgSize, maxState
}

func size_uni(p dv.Protocol, n int) (int, int) {
	alice, bob, _ := p.Init()

	msgSize := 0
	maxState := 0

	for i := 0; i < n/2; i++ {
		ct, _ := p.Send(alice, ad, msg)
		pt, _ := p.Receive(bob, ad, ct)
		_ = pt

		msgSize += len(ct)
		maxState = max(maxState, alice.Size())
		maxState = max(maxState, bob.Size())
	}

	for i := 0; i < n/2; i++ {
		ct, _ := p.Send(bob, ad, msg)
		pt, _ := p.Receive(alice, ad, ct)
		_ = pt

		msgSize += len(ct)
		maxState = max(maxState, alice.Size())
		maxState = max(maxState, bob.Size())
	}

	return msgSize, maxState
}

func size_def(p dv.Protocol, n int) (int, int) {
	alice, bob, _ := p.Init()

	msgSize := 0
	maxState := 0

	var cts [1000][]byte
	for i := 0; i < n/2; i++ {
		ct, _ := p.Send(alice, ad, msg)
		cts[i] = ct

		msgSize += len(ct)
		maxState = max(maxState, alice.Size())
	}

	for i := 0; i < n/2; i++ {
		ct, _ := p.Send(bob, ad, msg)
		pt, _ := p.Receive(alice, ad, ct)
		_ = pt

		msgSize += len(ct)
		maxState = max(maxState, alice.Size())
		maxState = max(maxState, bob.Size())
	}

	for i := 0; i < n/2; i++ {
		pt, _ := p.Receive(bob, ad, cts[i])
		_ = pt

		maxState = max(maxState, bob.Size())
	}

	return msgSize, maxState
}

func size(p dv.Protocol, tp func(p dv.Protocol, i int) (int, int)) {
	msg := make([]int, 20)

	s := ""
	for i, n := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100, 1200} {
		_, msg[i] = tp(p, n)
		s += fmt.Sprintf("(%d,%.2f)", n, float32(msg[i])/1000)
	}
	fmt.Println(s)
}

func max(a, b int) int {
	if a < b {
		return b
	}
	return a
}
