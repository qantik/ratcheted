// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

// Runtime, message size and state size benchmarks for the js protocol.
package main

import (
	"fmt"

	"github.com/qantik/ratcheted/primitives/hibe"
	"github.com/qantik/ratcheted/primitives/signature"
	"github.com/qantik/ratcheted/sch"
)

var (
	fsg    = signature.NewBellare()
	gentry = hibe.NewGentry()

	prt = sch.NewSCh(fsg, gentry)

	msg = []byte{
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
	}
)

func size_alternating(n int) {
	alice, bob, _ := prt.Init()

	maxMsg := 0
	maxState := 0

	for i := 0; i < n/2; i++ {
		ct, _ := prt.Send(alice, msg, msg)
		pt, _ := prt.Receive(bob, msg, ct)
		_ = pt

		maxMsg = max(maxMsg, len(ct))
		maxState = max(maxState, alice.Size())
		maxState = max(maxState, bob.Size())

		ct, _ = prt.Send(bob, msg, msg)
		pt, _ = prt.Receive(alice, msg, ct)
		_ = pt

		maxMsg = max(maxMsg, len(ct))
		maxState = max(maxState, alice.Size())
		maxState = max(maxState, bob.Size())
	}

	fmt.Printf("======= MSG SIZE\talternating(%d):\t%d\n", n, maxMsg)
	fmt.Printf("======= State SIZE\talternating(%d):\t%d\n", n, maxState)
}

func size_unidirectional(n int) {
	alice, bob, _ := prt.Init()

	maxMsg := 0
	maxState := 0

	for i := 0; i < n/2; i++ {
		ct, _ := prt.Send(alice, msg, msg)
		pt, _ := prt.Receive(bob, msg, ct)
		_ = pt

		maxMsg = max(maxMsg, len(ct))
		maxState = max(maxState, alice.Size())
		maxState = max(maxState, bob.Size())
	}

	for i := 0; i < n/2; i++ {
		ct, _ := prt.Send(bob, msg, msg)
		pt, _ := prt.Receive(alice, msg, ct)
		_ = pt

		maxMsg = max(maxMsg, len(ct))
		maxState = max(maxState, alice.Size())
		maxState = max(maxState, bob.Size())
	}

	fmt.Printf("======= MSG SIZE\tunidirectional(%d):\t%d\n", n, maxMsg)
	fmt.Printf("======= State SIZE\tunidirectional(%d):\t%d\n", n, maxState)
}

func size_def(n int) {
	alice, bob, _ := prt.Init()

	maxMsg := 0
	maxState := 0

	var cts [1000][]byte
	for i := 0; i < n/2; i++ {
		ct, _ := prt.Send(alice, msg, msg)
		cts[i] = ct

		maxMsg = max(maxMsg, len(ct))
		maxState = max(maxState, alice.Size())
	}

	for i := 0; i < n/2; i++ {
		ct, _ := prt.Send(bob, msg, msg)
		pt, _ := prt.Receive(alice, msg, ct)
		_ = pt

		maxMsg = max(maxMsg, len(ct))
		maxState = max(maxState, alice.Size())
		maxState = max(maxState, bob.Size())
	}

	for i := 0; i < n/2; i++ {
		pt, _ := prt.Receive(bob, msg, cts[i])
		_ = pt

		maxState = max(maxState, bob.Size())
	}

	fmt.Printf("======= MSG SIZE\tdef-unidirectional(%d):\t%d\n", n, maxMsg)
	fmt.Printf("======= State SIZE\tdef-unidirectional(%d):\t%d\n", n, maxState)
}

func main() {
	for _, n := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900} {
		size_alternating(n)
	}
	for _, n := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900} {
		size_unidirectional(n)
	}
	for _, n := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900} {
		size_def(n)
	}
}

func max(a, b int) int {
	if a < b {
		return b
	}
	return a
}
