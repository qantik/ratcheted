// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

// Runtime, message size and state size benchmarks for the acd protocol.
package main

import (
	"crypto/elliptic"
	"fmt"

	"github.com/qantik/ratcheted/dratch"
	"github.com/qantik/ratcheted/primitives/encryption"
	"github.com/qantik/ratcheted/primitives/signature"
)

var (
	curve = elliptic.P256()
	ecies = encryption.NewECIES(curve)
	ecdsa = signature.NewECDSA(curve)
	gcm   = encryption.NewGCM()

	dr   = dratch.NewDRatch(gcm, nil, nil)
	drpk = dratch.NewDRatch(gcm, ecies, ecdsa)

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

func size_alternating(dr *dratch.DRatch, n int) {
	alice, bob, _ := dr.Init()

	maxMsg := 0
	maxState := 0

	for i := 0; i < n/2; i++ {
		ct, _ := dr.Send(alice, msg)

		maxMsg = max(maxMsg, len(ct))
		maxState = max(maxState, alice.Size())
		maxState = max(maxState, bob.Size())

		pt, _ := dr.Receive(bob, ct)
		ct, _ = dr.Send(bob, msg)
		_ = pt

		maxMsg = max(maxMsg, len(ct))
		maxState = max(maxState, alice.Size())
		maxState = max(maxState, bob.Size())

		pt, _ = dr.Receive(alice, ct)
		_ = pt
	}

	fmt.Printf("======= MSG SIZE\talternating(%d):\t%d\n", n, maxMsg)
	fmt.Printf("======= STATE SIZE\talternating(%d):\t%d\n", n, maxState)
}

func size_unidirectional(dr *dratch.DRatch, n int) {
	alice, bob, _ := dr.Init()

	maxMsg := 0
	maxState := 0

	for i := 0; i < n/2; i++ {
		ct, _ := dr.Send(alice, msg)
		pt, _ := dr.Receive(bob, ct)
		_ = pt

		maxMsg = max(maxMsg, len(ct))
		maxState = max(maxState, alice.Size())
		maxState = max(maxState, bob.Size())
	}

	for i := 0; i < n/2; i++ {
		ct, _ := dr.Send(bob, msg)
		pt, _ := dr.Receive(alice, ct)
		_ = pt

		maxMsg = max(maxMsg, len(ct))
		maxState = max(maxState, alice.Size())
		maxState = max(maxState, bob.Size())
	}

	fmt.Printf("======= MSG SIZE\tunidirectional(%d):\t%d\n", n, maxMsg)
	fmt.Printf("======= STATE SIZE\tunidirectional(%d):\t%d\n", n, maxState)
}

func size_def(dr *dratch.DRatch, n int) {
	alice, bob, _ := dr.Init()

	maxMsg := 0
	maxState := 0

	var cts [1000][]byte
	for i := 0; i < n/2; i++ {
		ct, _ := dr.Send(alice, msg)
		cts[i] = ct

		maxMsg = max(maxMsg, len(ct))
		maxState = max(maxState, alice.Size())
	}

	for i := 0; i < n/2; i++ {
		ct, _ := dr.Send(bob, msg)
		pt, _ := dr.Receive(alice, ct)
		_ = pt

		maxMsg = max(maxMsg, len(ct))
		maxState = max(maxState, alice.Size())
		maxState = max(maxState, bob.Size())
	}

	for i := 0; i < n/2; i++ {
		pt, _ := dr.Receive(bob, cts[i])
		_ = pt

		maxState = max(maxState, bob.Size())
	}

	fmt.Printf("======= MSG SIZE\tdef-unidirectional(%d):\t%d\n", n, maxMsg)
	fmt.Printf("======= STATE SIZE\tdef-unidirectional(%d):\t%d\n", n, maxState)
}

func main() {
	for _, n := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900} {
		size_alternating(dr, n)
	}
	for _, n := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900} {
		size_unidirectional(dr, n)
	}
	for _, n := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900} {
		size_def(dr, n)
	}
}

func max(a, b int) int {
	if a < b {
		return b
	}
	return a
}
