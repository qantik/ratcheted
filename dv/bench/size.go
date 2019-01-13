// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package main

import (
	"crypto/elliptic"
	"fmt"

	"github.com/qantik/ratcheted/bark"
	"github.com/qantik/ratcheted/primitives/encryption"
	"github.com/qantik/ratcheted/primitives/signature"
)

var (
	curve = elliptic.P256()
	ecies = encryption.NewECIES(curve)
	ecdsa = signature.NewECDSA(curve)
	gcm   = encryption.NewGCM()

	prt  = bark.NewBARK(bark.NewUniARCAD(ecies, ecdsa))
	lite = bark.NewBARK(bark.NewLiteUniARCAD(gcm))
)

func size_alternating(bark *bark.BARK, n int) {
	alice, bob, _ := bark.Init()

	maxMsg := 0
	maxState := 0

	for i := 0; i < n/2; i++ {
		ka, ct, _ := bark.Send(alice)
		kb, _ := bark.Receive(bob, ct)
		_, _ = ka, kb

		maxMsg = max(maxMsg, len(ct))
		maxState = max(maxState, alice.Size())
		maxState = max(maxState, bob.Size())

		ka, ct, _ = bark.Send(bob)
		kb, _ = bark.Receive(alice, ct)
		_, _ = ka, kb

		maxMsg = max(maxMsg, len(ct))
		maxState = max(maxState, alice.Size())
		maxState = max(maxState, bob.Size())
	}

	fmt.Printf("======= MSG SIZE\talternating(%d):\t%d\n", n, maxMsg)
	fmt.Printf("======= STATE SIZE\talternating(%d):\t%d\n", n, maxState)
}

func size_unidirectional(bark *bark.BARK, n int) {
	alice, bob, _ := bark.Init()

	maxMsg := 0
	maxState := 0

	for i := 0; i < n/2; i++ {
		ka, ct, _ := bark.Send(alice)
		kb, _ := bark.Receive(bob, ct)
		_, _ = ka, kb

		maxMsg = max(maxMsg, len(ct))
		maxState = max(maxState, alice.Size())
		maxState = max(maxState, bob.Size())
	}

	for i := 0; i < n/2; i++ {
		ka, ct, _ := bark.Send(bob)
		kb, _ := bark.Receive(alice, ct)
		_, _ = ka, kb

		maxMsg = max(maxMsg, len(ct))
		maxState = max(maxState, alice.Size())
		maxState = max(maxState, bob.Size())
	}

	fmt.Printf("======= MSG SIZE\tunidirectional(%d):\t%d\n", n, maxMsg)
	fmt.Printf("======= STATE SIZE\tunidirectional(%d):\t%d\n", n, maxState)
}

func size_def(bark *bark.BARK, n int) {
	alice, bob, _ := bark.Init()

	maxMsg := 0
	maxState := 0

	var ks, cts [1000][]byte
	for i := 0; i < n/2; i++ {
		ka, ct, _ := bark.Send(alice)
		ks[i] = ka
		cts[i] = ct

		maxMsg = max(maxMsg, len(ct))
		maxState = max(maxState, alice.Size())
	}

	for i := 0; i < n/2; i++ {
		ka, ct, _ := bark.Send(bob)
		kb, _ := bark.Receive(alice, ct)
		_, _ = ka, kb

		maxMsg = max(maxMsg, len(ct))
		maxState = max(maxState, alice.Size())
		maxState = max(maxState, bob.Size())
	}

	for i := 0; i < n/2; i++ {
		kb, _ := bark.Receive(bob, cts[i])
		_ = kb

		maxState = max(maxState, bob.Size())
	}

	fmt.Printf("======= MSG SIZE\tdef-unidirectional(%d):\t%d\n", n, maxMsg)
	fmt.Printf("======= STATE SIZE\tdef-unidirectional(%d):\t%d\n", n, maxState)
}

func main() {
	for _, n := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900} {
		size_alternating(prt, n)
	}
	for _, n := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900} {
		size_unidirectional(prt, n)
	}
	for _, n := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900} {
		size_def(prt, n)
	}
}

func max(a, b int) int {
	if a < b {
		return b
	}
	return a
}
