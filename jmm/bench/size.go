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
)

var (
	msg = []byte("msg")
	ad  = []byte("ad")
)

func size_alternating(n int) (int, int) {
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

func size_unidirectional(n int) (int, int) {
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

	var cts [1000][]byte
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

func main() {
	msg := make([]int, 10)

	s := ""
	for i, n := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900} {
		msg[i], _ = size_alternating(n)
		s += fmt.Sprintf("(%d,%.2f)", n, float32(msg[i])/1000)
	}
	fmt.Println("Total Message Size (ALT)\n", s)

	s = ""
	for i, n := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900} {
		msg[i], _ = size_unidirectional(n)
		s += fmt.Sprintf("(%d,%.2f)", n, float32(msg[i])/1000)
	}
	fmt.Println("Total Message Size (UNI)\n", s)

	s = ""
	for i, n := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900} {
		msg[i], _ = size_def(n)
		s += fmt.Sprintf("(%d,%.2f)", n, float32(msg[i])/1000)
	}
	fmt.Println("Total Message Size (DEF)\n", s)
}

func max(a, b int) int {
	if a < b {
		return b
	}
	return a
}
