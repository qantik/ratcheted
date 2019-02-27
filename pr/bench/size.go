// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

// Runtime, message size and state size benchmarks for the pr protocol.
package main

import (
	"fmt"
)

func size_alt(n int) (int, int) {
	alice, bob, _ := brke.Init()

	msgSize := 0
	maxState := 0

	for i := 0; i < n/2; i++ {
		ka, c, _ := brke.Send(alice, ad)
		kb, _ := brke.Receive(bob, ad, c)
		_, _ = ka, kb

		msgSize += mSize(c)
		//maxState = max(maxState, alice.Size())
		//maxState = max(maxState, bob.Size())

		kb, c, _ = brke.Send(bob, ad)
		ka, _ = brke.Receive(alice, ad, c)
		_, _ = ka, kb

		//msgSize = max(msgSize, size(c))
		msgSize += mSize(c)
		//maxState = max(maxState, alice.Size())
		//maxState = max(maxState, bob.Size())
	}

	return msgSize, maxState
}

func size_uni(n int) (int, int) {
	alice, bob, _ := brke.Init()

	msgSize := 0
	maxState := 0

	for i := 0; i < n/2; i++ {
		ka, c, _ := brke.Send(alice, ad)
		kb, _ := brke.Receive(bob, ad, c)
		_, _ = ka, kb

		msgSize += mSize(c)
		//maxState = max(maxState, alice.Size())
		//maxState = max(maxState, bob.Size())
	}

	for i := 0; i < n/2; i++ {
		kb, c, _ := brke.Send(bob, ad)
		ka, _ := brke.Receive(alice, ad, c)
		_, _ = ka, kb

		msgSize += mSize(c)
		//maxState = max(maxState, alice.Size())
		//maxState = max(maxState, bob.Size())
	}

	return msgSize, maxState
}

func size_def(n int) (int, int) {
	alice, bob, _ := brke.Init()

	msgSize := 0
	maxState := 0

	var ks [1200][]byte
	var cs [1200][][]byte
	for i := 0; i < n/2; i++ {
		k, c, _ := brke.Send(alice, ad)
		ks[i] = k
		cs[i] = c

		msgSize += mSize(c)
		//maxState = max(maxState, alice.Size())
	}

	for i := 0; i < n/2; i++ {
		kb, c, _ := brke.Send(bob, ad)
		ka, _ := brke.Receive(alice, ad, c)
		_, _ = ka, kb

		msgSize += mSize(c)
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

func size(tp func(i int) (int, int)) {
	msg := make([]int, 10)

	s := ""
	for i, n := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900} {
		msg[i], _ = tp(n)
		s += fmt.Sprintf("(%d,%.2f)", n, float32(msg[i])/1000)
	}
	fmt.Println(s)
}

// func main() {
// 	msg := make([]int, 10)

// 	s := ""
// 	for i, n := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900} {
// 		msg[i], _ = size_alternating(n)
// 		s += fmt.Sprintf("(%d,%.2f)", n, float32(msg[i])/1000)
// 	}
// 	fmt.Println("Total Message Size (ALT)\n", s)

// 	s = ""
// 	for i, n := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900} {
// 		msg[i], _ = size_unidirectional(n)
// 		s += fmt.Sprintf("(%d,%.2f)", n, float32(msg[i])/1000)
// 		fmt.Println(s)
// 	}
// 	fmt.Println("Total Message Size (UNI)\n", s)

// 	s = ""
// 	for i, n := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900} {
// 		msg[i], _ = size_def(n)
// 		s += fmt.Sprintf("(%d,%.2f)", n, float32(msg[i])/1000)
// 		fmt.Println(s)
// 	}
// 	fmt.Println("Total Message Size (DEF)\n", s)
// }

func max(a, b int) int {
	if a < b {
		return b
	}
	return a
}

func mSize(m [][]byte) int {
	size := 0
	for _, b := range m {
		size += len(b)
	}
	return size
}
