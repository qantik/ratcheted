// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package main

import (
	"crypto/elliptic"
	"fmt"

	"github.com/qantik/ratcheted/brke"
	"github.com/qantik/ratcheted/primitives/hibe"
	"github.com/qantik/ratcheted/primitives/signature"
)

var (
	curve  = elliptic.P256()
	ecdsa  = signature.NewECDSA(curve)
	gentry = hibe.NewGentry()

	prt = brke.NewBRKE(gentry, ecdsa)

	ad = []byte{
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
		ka, c, _ := prt.Send(alice, ad)
		kb, _ := prt.Receive(bob, ad, c)
		_, _ = ka, kb

		maxMsg = max(maxMsg, size(c))
		maxState = max(maxState, alice.Size())
		maxState = max(maxState, bob.Size())

		kb, c, _ = prt.Send(bob, ad)
		ka, _ = prt.Receive(alice, ad, c)
		_, _ = ka, kb

		maxMsg = max(maxMsg, size(c))
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
		ka, c, _ := prt.Send(alice, ad)
		kb, _ := prt.Receive(bob, ad, c)
		_, _ = ka, kb

		maxMsg = max(maxMsg, size(c))
		maxState = max(maxState, alice.Size())
		maxState = max(maxState, bob.Size())
	}

	for i := 0; i < n/2; i++ {
		kb, c, _ := prt.Send(bob, ad)
		ka, _ := prt.Receive(alice, ad, c)
		_, _ = ka, kb

		maxMsg = max(maxMsg, size(c))
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

	var ks [1000][]byte
	var cs [1000][][]byte
	for i := 0; i < n/2; i++ {
		k, c, _ := prt.Send(alice, ad)
		ks[i] = k
		cs[i] = c

		maxMsg = max(maxMsg, size(c))
		maxState = max(maxState, alice.Size())
	}

	for i := 0; i < n/2; i++ {
		kb, c, _ := prt.Send(bob, ad)
		ka, _ := prt.Receive(alice, ad, c)
		_, _ = ka, kb

		maxMsg = max(maxMsg, size(c))
		maxState = max(maxState, alice.Size())
		maxState = max(maxState, bob.Size())
	}

	for i := 0; i < n/2; i++ {
		k, _ := prt.Receive(bob, ad, cs[i])
		_ = k

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

func size(m [][]byte) int {
	size := 0
	for _, b := range m {
		size += len(b)
	}
	return size
}
