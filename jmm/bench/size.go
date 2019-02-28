// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

// Runtime, message size and state size benchmarks for the jmm protocol.
package main

import (
	"fmt"
)

func size_alt(n int) (int, int) {
	alice, bob, _ := sec.Init()

	msgSize := 0
	maxState := 0

	for i := 0; i < n/2; i++ {
		ct, _ := sec.Send(alice, msg)
		pt, _ := sec.Receive(bob, ct)
		_ = pt

		msgSize += len(ct)
		//maxState = max(maxState, alice.Size())
		//maxState = max(maxState, bob.Size())

		ct, _ = sec.Send(bob, msg)
		pt, _ = sec.Receive(alice, ct)
		_ = pt

		msgSize += len(ct)
		//maxState = max(maxState, alice.Size())
		//maxState = max(maxState, bob.Size())
	}

	return msgSize, maxState
}

func size_uni(n int) (int, int) {
	alice, bob, _ := sec.Init()

	msgSize := 0
	maxState := 0

	for i := 0; i < n/2; i++ {
		ct, _ := sec.Send(alice, msg)
		pt, _ := sec.Receive(bob, ct)
		_ = pt

		msgSize += len(ct)
		//maxState = max(maxState, alice.Size())
		//maxState = max(maxState, bob.Size())
	}

	for i := 0; i < n/2; i++ {
		ct, _ := sec.Send(bob, msg)
		pt, _ := sec.Receive(alice, ct)
		_ = pt

		msgSize += len(ct)
		//maxState = max(maxState, alice.Size())
		//maxState = max(maxState, bob.Size())
	}

	return msgSize, maxState
}

func size_def(n int) (int, int) {
	alice, bob, _ := sec.Init()

	msgSize := 0
	maxState := 0

	var cts [1200][]byte
	for i := 0; i < n/2; i++ {
		ct, _ := sec.Send(alice, msg)
		cts[i] = ct

		msgSize += len(ct)
		//maxState = max(maxState, alice.Size())
	}

	for i := 0; i < n/2; i++ {
		ct, _ := sec.Send(bob, msg)
		pt, _ := sec.Receive(alice, ct)
		_ = pt

		msgSize += len(ct)
		//maxState = max(maxState, alice.Size())
		//maxState = max(maxState, bob.Size())
	}

	for i := 0; i < n/2; i++ {
		pt, _ := sec.Receive(bob, cts[i])
		_ = pt

		maxState = max(maxState, bob.Size())
	}

	return msgSize, maxState
}

func size(tp func(i int) (int, int)) {
	msg := make([]int, 20)

	s := ""
	for i, n := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100, 1200} {
		msg[i], _ = tp(n)
		s += fmt.Sprintf("(%d,%.2f)", n, float32(msg[i])/1000)
	}
	fmt.Println(s)
}

// func main() {
// 	msg := make([]int, 10)

// 	s := ""
// 	for i, n := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900} {
// 		msg[i], _ = size_alternating(n)
// 		s += fmt.Sprintf("(%d,%.2f)", n, float32(msg[i])/1000)
// 	}
// 	fmt.Println("Total Message Size (ALT)\n", s)

// 	s = ""
// 	for i, n := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900} {
// 		msg[i], _ = size_unidirectional(n)
// 		s += fmt.Sprintf("(%d,%.2f)", n, float32(msg[i])/1000)
// 	}
// 	fmt.Println("Total Message Size (UNI)\n", s)

// 	s = ""
// 	for i, n := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900} {
// 		msg[i], _ = size_def(n)
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
