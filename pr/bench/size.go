// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

// Runtime, message size and state size benchmarks for the pr protocol.
package main

import (
	"crypto/elliptic"
	"fmt"

	"github.com/qantik/ratcheted/pr"
	"github.com/qantik/ratcheted/primitives/hibe"
	"github.com/qantik/ratcheted/primitives/signature"
)

var (
	curve  = elliptic.P256()
	ecdsa  = signature.NewECDSA(curve)
	gentry = hibe.NewGentry()

	brke = pr.NewBRKE(gentry, ecdsa)
)

var (
	msg = []byte("msg")
	ad  = []byte("ad")
)

func size_alternating(n int) (int, int) {
	alice, bob, _ := brke.Init()

	msgSize := 0
	maxState := 0

	for i := 0; i < n/2; i++ {
		ka, c, _ := brke.Send(alice, ad)
		kb, _ := brke.Receive(bob, ad, c)
		_, _ = ka, kb

		msgSize += size(c)
		//maxState = max(maxState, alice.Size())
		//maxState = max(maxState, bob.Size())

		kb, c, _ = brke.Send(bob, ad)
		ka, _ = brke.Receive(alice, ad, c)
		_, _ = ka, kb

		//msgSize = max(msgSize, size(c))
		msgSize += size(c)
		//maxState = max(maxState, alice.Size())
		//maxState = max(maxState, bob.Size())
	}

	return msgSize, maxState
}

func size_unidirectional(n int) (int, int) {
	alice, bob, _ := brke.Init()

	msgSize := 0
	maxState := 0

	for i := 0; i < n/2; i++ {
		ka, c, _ := brke.Send(alice, ad)
		kb, _ := brke.Receive(bob, ad, c)
		_, _ = ka, kb

		msgSize += size(c)
		//maxState = max(maxState, alice.Size())
		//maxState = max(maxState, bob.Size())
	}

	for i := 0; i < n/2; i++ {
		kb, c, _ := brke.Send(bob, ad)
		ka, _ := brke.Receive(alice, ad, c)
		_, _ = ka, kb

		msgSize += size(c)
		//maxState = max(maxState, alice.Size())
		//maxState = max(maxState, bob.Size())
	}

	return msgSize, maxState
}

func size_def(n int) (int, int) {
	alice, bob, _ := brke.Init()

	msgSize := 0
	maxState := 0

	var ks [1000][]byte
	var cs [1000][][]byte
	for i := 0; i < n/2; i++ {
		k, c, _ := brke.Send(alice, ad)
		ks[i] = k
		cs[i] = c

		msgSize += size(c)
		//maxState = max(maxState, alice.Size())
	}

	for i := 0; i < n/2; i++ {
		kb, c, _ := brke.Send(bob, ad)
		ka, _ := brke.Receive(alice, ad, c)
		_, _ = ka, kb

		msgSize += size(c)
		//maxState = max(maxState, alice.Size())
		//maxState = max(maxState, bob.Size())
	}

	for i := 0; i < n/2; i++ {
		k, _ := brke.Receive(bob, ad, cs[i])
		_ = k

		maxState = max(maxState, bob.Size())
	}

	return msgSize, maxState
}

func main() {
	msg := make([]int, 10)

	s := ""
	//for i, n := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900} {
	//	msg[i], _ = size_alternating(n)
	//	s += fmt.Sprintf("(%d,%.2f)", n, float32(msg[i])/1000)
	//}
	//fmt.Println("Total Message Size (ALT)\n", s)

	// s = ""
	// for i, n := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900} {
	// 	msg[i], _ = size_unidirectional(n)
	// 	s += fmt.Sprintf("(%d,%.2f)", n, float32(msg[i])/1000)
	// 	fmt.Println(s)
	// }
	// fmt.Println("Total Message Size (UNI)\n", s)

	s = ""
	for i, n := range []int{200, 300, 400, 500, 600, 700, 800, 900} {
		msg[i], _ = size_def(n)
		s += fmt.Sprintf("(%d,%.2f)", n, float32(msg[i])/1000)
		fmt.Println(s)
	}
	fmt.Println("Total Message Size (DEF)\n", s)
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
