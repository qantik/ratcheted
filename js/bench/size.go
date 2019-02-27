// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

// Runtime, message size and state size benchmarks for the js protocol.
package main

import (
	"fmt"
)

func size_alt(n int) (int, int) {
	alice, bob, _ := sch.Init()

	msgSize := 0
	maxState := 0

	for i := 0; i < n/2; i++ {
		ct, _ := sch.Send(alice, msg, msg)
		pt, _ := sch.Receive(bob, msg, ct)
		_ = pt

		msgSize += len(ct)
		//maxState = max(maxState, alice.Size())
		//maxState = max(maxState, bob.Size())

		ct, _ = sch.Send(bob, msg, msg)
		pt, _ = sch.Receive(alice, msg, ct)
		_ = pt

		msgSize += len(ct)
		//maxState = max(maxState, alice.Size())
		//maxState = max(maxState, bob.Size())
	}

	return msgSize, maxState
}

func size_uni(n int) (int, int) {
	alice, bob, _ := sch.Init()

	msgSize := 0
	maxState := 0

	for i := 0; i < n/2; i++ {
		ct, _ := sch.Send(alice, msg, msg)
		pt, _ := sch.Receive(bob, msg, ct)
		_ = pt

		msgSize += len(ct)
		//maxState = max(maxState, alice.Size())
		//maxState = max(maxState, bob.Size())
	}

	for i := 0; i < n/2; i++ {
		ct, _ := sch.Send(bob, msg, msg)
		pt, _ := sch.Receive(alice, msg, ct)
		_ = pt

		msgSize += len(ct)
		//maxState = max(maxState, alice.Size())
		//maxState = max(maxState, bob.Size())
	}

	return msgSize, maxState
}

func size_def(n int) (int, int) {
	alice, bob, _ := sch.Init()

	msgSize := 0
	maxState := 0

	var cts [1000][]byte
	for i := 0; i < n/2; i++ {
		ct, _ := sch.Send(alice, msg, msg)
		cts[i] = ct

		msgSize += len(ct)
		maxState = max(maxState, alice.Size())
	}

	for i := 0; i < n/2; i++ {
		ct, _ := sch.Send(bob, msg, msg)
		pt, _ := sch.Receive(alice, msg, ct)
		_ = pt

		msgSize += len(ct)
		//maxState = max(maxState, alice.Size())
		//maxState = max(maxState, bob.Size())
	}

	for i := 0; i < n/2; i++ {
		pt, _ := sch.Receive(bob, msg, cts[i])
		_ = pt

		maxState = max(maxState, bob.Size())
	}

	return msgSize, maxState
}

func size(tp func(i int) (int, int)) {
	msg := make([]int, 10)

	s := ""
	for i, n := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900} {
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
// 		fmt.Println(s)
// 	}
// 	fmt.Println("Total Message Size (DEF)\n", s)
// }

func max(a, b int) int {
	if a < b {
		return b
	}
	return a
}
