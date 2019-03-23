// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

// Runtime, message size and state size benchmarks for the acd protocol.
package main

import (
	"fmt"

	"github.com/qantik/ratcheted/acd"
)

func size_alt(dr *acd.DoubleRatchet, n int) (int, int) {
	alice, bob, _ := dr.Init()

	msgSize := 0
	maxState := 0

	for i := 0; i < n/2; i++ {
		ct, _ := dr.Send(alice, msg)

		msgSize += len(ct)
		maxState = max(maxState, alice.Size())
		maxState = max(maxState, bob.Size())

		pt, _ := dr.Receive(bob, ct)
		ct, _ = dr.Send(bob, msg)
		_ = pt

		msgSize += len(ct)
		maxState = max(maxState, alice.Size())
		maxState = max(maxState, bob.Size())

		pt, _ = dr.Receive(alice, ct)
		_ = pt
	}

	return msgSize, maxState
}

func size_uni(dr *acd.DoubleRatchet, n int) (int, int) {
	alice, bob, _ := dr.Init()

	msgSize := 0
	maxState := 0

	for i := 0; i < n/2; i++ {
		ct, _ := dr.Send(alice, msg)
		pt, _ := dr.Receive(bob, ct)
		_ = pt

		msgSize += len(ct)
		maxState = max(maxState, alice.Size())
		maxState = max(maxState, bob.Size())
	}

	for i := 0; i < n/2; i++ {
		ct, _ := dr.Send(bob, msg)
		pt, _ := dr.Receive(alice, ct)
		_ = pt

		msgSize += len(ct)
		maxState = max(maxState, alice.Size())
		maxState = max(maxState, bob.Size())
	}

	return msgSize, maxState
}

func size_def(dr *acd.DoubleRatchet, n int) (int, int) {
	alice, bob, _ := dr.Init()

	msgSize := 0
	maxState := 0

	var cts [1200][]byte
	for i := 0; i < n/2; i++ {
		ct, _ := dr.Send(alice, msg)
		cts[i] = ct

		msgSize += len(ct)
		maxState = max(maxState, alice.Size())
	}

	for i := 0; i < n/2; i++ {
		ct, _ := dr.Send(bob, msg)
		pt, _ := dr.Receive(alice, ct)
		_ = pt

		msgSize += len(ct)
		maxState = max(maxState, alice.Size())
		maxState = max(maxState, bob.Size())
	}

	for i := 0; i < n/2; i++ {
		pt, _ := dr.Receive(bob, cts[i])
		_ = pt

		maxState = max(maxState, bob.Size())
	}

	return msgSize, maxState
}

func size(p *acd.DoubleRatchet, tp func(p *acd.DoubleRatchet, i int) (int, int)) {
	msg := make([]int, 20)

	s := ""
	for i, n := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100, 1200} {
		_, msg[i] = tp(p, n)
		s += fmt.Sprintf("(%d,%.2f)", n, float32(msg[i])/1000)
	}
	fmt.Println(s)
}

// func main() {
// 	msg := make([]int, 10)

// 	s := ""
// 	for i, n := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900} {
// 		msg[i], _ = size_alternating(drpk, n)
// 		s += fmt.Sprintf("(%d,%.2f)", n, float32(msg[i])/1000)
// 	}
// 	fmt.Println("Total Message Size (ALT)\n", s)

// 	s = ""
// 	for i, n := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900} {
// 		msg[i], _ = size_unidirectional(drpk, n)
// 		s += fmt.Sprintf("(%d,%.2f)", n, float32(msg[i])/1000)
// 	}
// 	fmt.Println("Total Message Size (UNI)\n", s)

// 	s = ""
// 	for i, n := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900} {
// 		msg[i], _ = size_def(drpk, n)
// 		s += fmt.Sprintf("(%d,%.2f)", n, float32(msg[i])/1000)
// 	}
// 	fmt.Println("Total Message Size (DEF)\n", s)
// }

func max(a, b int) int {
	if a < b {
		return b
	}
	return a
}
