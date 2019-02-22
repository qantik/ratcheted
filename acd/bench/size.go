// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

// Runtime, message size and state size benchmarks for the acd protocol.
package main

import (
	"crypto/elliptic"
	"fmt"

	"github.com/qantik/ratcheted/acd"
	"github.com/qantik/ratcheted/primitives/encryption"
	"github.com/qantik/ratcheted/primitives/signature"
)

var (
	curve = elliptic.P256()
	ecies = encryption.NewECIES(curve)
	ecdsa = signature.NewECDSA(curve)
	gcm   = encryption.NewGCM()

	dr   = acd.NewDoubleRatchet(gcm, nil, nil)
	drpk = acd.NewDoubleRatchet(gcm, ecies, ecdsa)
)

var (
	msg = []byte("msg")
	ad  = []byte("ad")
)

func size_alternating(dr *acd.DoubleRatchet, n int) (int, int) {
	alice, bob, _ := dr.Init()

	msgSize := 0
	maxState := 0

	for i := 0; i < n/2; i++ {
		ct, _ := dr.Send(alice, msg)

		msgSize += len(ct)
		//maxState = max(maxState, alice.Size())
		//maxState = max(maxState, bob.Size())

		pt, _ := dr.Receive(bob, ct)
		ct, _ = dr.Send(bob, msg)
		_ = pt

		msgSize += len(ct)
		//maxState = max(maxState, alice.Size())
		//maxState = max(maxState, bob.Size())

		pt, _ = dr.Receive(alice, ct)
		_ = pt
	}

	return msgSize, maxState
}

func size_unidirectional(dr *acd.DoubleRatchet, n int) (int, int) {
	alice, bob, _ := dr.Init()

	msgSize := 0
	maxState := 0

	for i := 0; i < n/2; i++ {
		ct, _ := dr.Send(alice, msg)
		pt, _ := dr.Receive(bob, ct)
		_ = pt

		msgSize += len(ct)
		//maxState = max(maxState, alice.Size())
		//maxState = max(maxState, bob.Size())
	}

	for i := 0; i < n/2; i++ {
		ct, _ := dr.Send(bob, msg)
		pt, _ := dr.Receive(alice, ct)
		_ = pt

		msgSize += len(ct)
		//maxState = max(maxState, alice.Size())
		//maxState = max(maxState, bob.Size())
	}

	return msgSize, maxState
}

func size_def(dr *acd.DoubleRatchet, n int) (int, int) {
	alice, bob, _ := dr.Init()

	msgSize := 0
	maxState := 0

	var cts [1000][]byte
	for i := 0; i < n/2; i++ {
		ct, _ := dr.Send(alice, msg)
		cts[i] = ct

		msgSize += len(ct)
		//maxState = max(maxState, alice.Size())
	}

	for i := 0; i < n/2; i++ {
		ct, _ := dr.Send(bob, msg)
		pt, _ := dr.Receive(alice, ct)
		_ = pt

		msgSize += len(ct)
		//maxState = max(maxState, alice.Size())
		//maxState = max(maxState, bob.Size())
	}

	for i := 0; i < n/2; i++ {
		pt, _ := dr.Receive(bob, cts[i])
		_ = pt

		//maxState = max(maxState, bob.Size())
	}

	return msgSize, maxState
}

func main() {
	msg := make([]int, 10)
	for i, n := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900} {
		msg[i], _ = size_alternating(dr, n)
	}
	fmt.Println("Total Message Size (ALT)", msg)
	for i, n := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900} {
		msg[i], _ = size_unidirectional(dr, n)
	}
	fmt.Println("Total Message Size (UNI)", msg)
	for i, n := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900} {
		msg[i], _ = size_def(dr, n)
	}
	fmt.Println("Total Message Size (DEF)", msg)
}

func max(a, b int) int {
	if a < b {
		return b
	}
	return a
}
