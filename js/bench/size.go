// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

// Runtime, message size and state size benchmarks for the js protocol.
package main

import (
	"fmt"

	"github.com/qantik/ratcheted/js"
	"github.com/qantik/ratcheted/primitives/hibe"
	"github.com/qantik/ratcheted/primitives/signature"
)

var (
	fsg    = signature.NewBellare()
	gentry = hibe.NewGentry()

	sch = js.NewSCh(fsg, gentry)
)

var (
	msg = []byte("msg")
	ad  = []byte("ad")
)

func size_alternating(n int) (int, int) {
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

func size_unidirectional(n int) (int, int) {
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

func main() {
	msg := make([]int, 10)
	//for i, n := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900} {
	//	msg[i], _ = size_alternating(n)
	//	fmt.Println(msg[i])
	//}
	//fmt.Println("Total Message Size (ALT)", msg)
	for i, n := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900} {
		msg[i], _ = size_unidirectional(n)
		fmt.Println(msg[i])
	}
	fmt.Println("Total Message Size (UNI)", msg)
	for i, n := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900} {
		msg[i], _ = size_def(n)
	}
	fmt.Println("Total Message Size (DEF)", msg)
}

func max(a, b int) int {
	if a < b {
		return b
	}
	return a
}
