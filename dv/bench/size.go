// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

// Runtime, message size and state size benchmarks for the dv protocol.
package main

import (
	"crypto/elliptic"
	"fmt"

	"github.com/qantik/ratcheted/dv"
	"github.com/qantik/ratcheted/primitives/encryption"
	"github.com/qantik/ratcheted/primitives/signature"
)

var (
	curve = elliptic.P256()
	ecies = encryption.NewECIES(curve)
	ecdsa = signature.NewECDSA(curve)
	gcm   = encryption.NewGCM()

	bark = dv.NewBARK(dv.NewUniARCAD(ecies, ecdsa))
	//lite = dv.NewBARK(dv.NewLiteUniARCAD(gcm))
)

func size_alternating(bark *dv.BARK, n int) {
	alice, bob, _ := bark.Init()

	maxMsg := 0
	totalMsgAlice := 0
	totalMsgBob := 0
	maxState := 0

	for i := 0; i < n/2; i++ {
		ka, ct, _ := bark.Send(alice)
		kb, _ := bark.Receive(bob, ct)
		_, _ = ka, kb

		maxMsg = max(maxMsg, len(ct))
		totalMsgAlice += len(ct)

		maxState = max(maxState, alice.Size())
		maxState = max(maxState, bob.Size())

		ka, ct, _ = bark.Send(bob)
		kb, _ = bark.Receive(alice, ct)
		_, _ = ka, kb

		maxMsg = max(maxMsg, len(ct))
		totalMsgBob += len(ct)

		maxState = max(maxState, alice.Size())
		maxState = max(maxState, bob.Size())
	}

	fmt.Printf("======= MAX MSG\talternating(%d):\t%d\n", n, maxMsg)
	fmt.Printf("======= ALICE MSG\talternating(%d):\t%d\n", n, totalMsgAlice)
	fmt.Printf("======= BOB MSG\t\talternating(%d):\t%d\n", n, totalMsgBob)
	fmt.Printf("======= STATE SIZE\talternating(%d):\t%d\n", n, maxState)

}

func size_unidirectional(bark *dv.BARK, n int) {
	alice, bob, _ := bark.Init()

	maxMsg := 0
	totalMsgAlice := 0
	totalMsgBob := 0
	maxState := 0

	for i := 0; i < n/2; i++ {
		ka, ct, _ := bark.Send(alice)
		kb, _ := bark.Receive(bob, ct)
		_, _ = ka, kb

		maxMsg = max(maxMsg, len(ct))
		totalMsgAlice += len(ct)

		maxState = max(maxState, alice.Size())
		maxState = max(maxState, bob.Size())
	}

	for i := 0; i < n/2; i++ {
		ka, ct, _ := bark.Send(bob)
		kb, _ := bark.Receive(alice, ct)
		_, _ = ka, kb

		maxMsg = max(maxMsg, len(ct))
		totalMsgBob += len(ct)

		maxState = max(maxState, alice.Size())
		maxState = max(maxState, bob.Size())
	}

	fmt.Printf("======= MSG SIZE\tunidirectional(%d):\t%d\n", n, maxMsg)
	fmt.Printf("======= ALICE MSG\tunidirectional(%d):\t%d\n", n, totalMsgAlice)
	fmt.Printf("======= BOB MSG\t\tunidirectional(%d):\t%d\n", n, totalMsgBob)
	fmt.Printf("======= STATE SIZE\tunidirectional(%d):\t%d\n", n, maxState)
}

func size_def(bark *dv.BARK, n int) {
	alice, bob, _ := bark.Init()

	maxMsg := 0
	totalMsgAlice := 0
	totalMsgBob := 0
	maxState := 0

	var ks, cts [1000][]byte
	for i := 0; i < n/2; i++ {
		ka, ct, _ := bark.Send(alice)
		ks[i] = ka
		cts[i] = ct

		maxMsg = max(maxMsg, len(ct))
		totalMsgAlice += len(ct)

		maxState = max(maxState, alice.Size())
	}

	for i := 0; i < n/2; i++ {
		ka, ct, _ := bark.Send(bob)
		kb, _ := bark.Receive(alice, ct)
		_, _ = ka, kb

		maxMsg = max(maxMsg, len(ct))
		totalMsgBob += len(ct)

		maxState = max(maxState, alice.Size())
		maxState = max(maxState, bob.Size())
	}

	for i := 0; i < n/2; i++ {
		kb, _ := bark.Receive(bob, cts[i])
		_ = kb

		maxState = max(maxState, bob.Size())
	}

	fmt.Printf("======= MSG SIZE\tdef-unidirectional(%d):\t%d\n", n, maxMsg)
	fmt.Printf("======= ALICE MSG\tdef-unidirectional(%d):\t%d\n", n, totalMsgAlice)
	fmt.Printf("======= BOB MSG\t\tdef-unidirectional(%d):\t%d\n", n, totalMsgBob)
	fmt.Printf("======= STATE SIZE\tdef-unidirectional(%d):\t%d\n", n, maxState)
}

func main() {
	for _, n := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900} {
		size_alternating(bark, n)
	}
	for _, n := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900} {
		size_unidirectional(bark, n)
	}
	for _, n := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900} {
		size_def(bark, n)
	}
}

func max(a, b int) int {
	if a < b {
		return b
	}
	return a
}
