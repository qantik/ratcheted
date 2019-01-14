// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

// Runtime, message size and state size benchmarks for the jmm protocol.
package main

import (
	"crypto/elliptic"
	"fmt"

	"github.com/qantik/ratcheted/jmm"
	"github.com/qantik/ratcheted/primitives/encryption"
	"github.com/qantik/ratcheted/primitives/signature"
)

var (
	curve = elliptic.P256()
	ecdsa = signature.NewECDSA(curve)
	ecies = encryption.NewECIES(curve)

	sec = jmm.NewSecMsg(ecies, ecdsa)

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
	alice, bob, _ := sec.Init()

	maxMsg := 0
	maxState := 0

	for i := 0; i < n/2; i++ {
		ct, _ := sec.Send(alice, msg)
		pt, _ := sec.Receive(bob, ct)
		_ = pt

		maxMsg = max(maxMsg, len(ct))
		maxState = max(maxState, alice.Size())
		maxState = max(maxState, bob.Size())

		ct, _ = sec.Send(bob, msg)
		pt, _ = sec.Receive(alice, ct)
		_ = pt

		maxMsg = max(maxMsg, len(ct))
		maxState = max(maxState, alice.Size())
		maxState = max(maxState, bob.Size())
	}

	fmt.Printf("======= MSG SIZE\talternating(%d):\t%d\n", n, maxMsg)
	fmt.Printf("======= STATE SIZE\talternating(%d):\t%d\n", n, maxState)
}

func size_unidirectional(n int) {
	alice, bob, _ := sec.Init()

	maxMsg := 0
	maxState := 0

	for i := 0; i < n/2; i++ {
		ct, _ := sec.Send(alice, msg)
		pt, _ := sec.Receive(bob, ct)
		_ = pt

		maxMsg = max(maxMsg, len(ct))
		maxState = max(maxState, alice.Size())
		maxState = max(maxState, bob.Size())
	}

	for i := 0; i < n/2; i++ {
		ct, _ := sec.Send(bob, msg)
		pt, _ := sec.Receive(alice, ct)
		_ = pt

		maxMsg = max(maxMsg, len(ct))
		maxState = max(maxState, alice.Size())
		maxState = max(maxState, bob.Size())
	}

	fmt.Printf("======= MSG SIZE\tunidirectional(%d):\t%d\n", n, maxMsg)
	fmt.Printf("======= STATE SIZE\tunidirectional(%d):\t%d\n", n, maxState)
}

func size_def(n int) {
	alice, bob, _ := sec.Init()

	maxMsg := 0
	maxState := 0

	var cts [1000][]byte
	for i := 0; i < n/2; i++ {
		ct, _ := sec.Send(alice, msg)
		cts[i] = ct

		maxMsg = max(maxMsg, len(ct))
		maxState = max(maxState, alice.Size())
	}

	for i := 0; i < n/2; i++ {
		ct, _ := sec.Send(bob, msg)
		pt, _ := sec.Receive(alice, ct)
		_ = pt

		maxMsg = max(maxMsg, len(ct))
		maxState = max(maxState, alice.Size())
		maxState = max(maxState, bob.Size())
	}

	for i := 0; i < n/2; i++ {
		pt, _ := sec.Receive(bob, cts[i])
		_ = pt

		maxState = max(maxState, bob.Size())
	}

	fmt.Printf("======= MSG SIZE\tdef-unidirectional(%d):\t%d\n", n, maxMsg)
	fmt.Printf("======= STATE SIZE\tdef-unidirectional(%d):\t%d\n", n, maxState)
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
