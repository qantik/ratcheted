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
	aes   = encryption.NewAES()

	//bark      = dv.NewBARK(dv.NewUniARCAD(ecies, ecdsa))
	arcad  = dv.NewARCAD(ecdsa, ecies, aes)
	lite   = dv.NewLiteARCAD(gcm, aes)
	hybrid = dv.NewHybridARCAD(ecdsa, ecies, aes, gcm)
	//lite      = dv.NewBARK(dv.NewLiteUniARCAD(gcm))
)

var (
	msg = []byte("msg")
	ad  = []byte("ad")
)

func size_alternating(arcad *dv.ARCAD, n int) (int, int) {
	alice, bob, _ := arcad.Init()

	msgSize := 0
	maxState := 0

	for i := 0; i < n/2; i++ {
		ct, _ := arcad.Send(alice, ad, msg)
		pt, _ := arcad.Receive(bob, ad, ct)
		_ = pt

		msgSize += len(ct)
		//maxState = max(maxState, alice.Size())
		//maxState = max(maxState, bob.Size())

		ct, _ = arcad.Send(bob, ad, msg)
		pt, _ = arcad.Receive(alice, ad, ct)
		_ = pt

		msgSize += len(ct)
		//maxState = max(maxState, alice.Size())
		//maxState = max(maxState, bob.Size())
	}

	return msgSize, maxState
}

func size_unidirectional(arcad *dv.ARCAD, n int) (int, int) {
	alice, bob, _ := arcad.Init()

	msgSize := 0
	maxState := 0

	for i := 0; i < n/2; i++ {
		ct, _ := arcad.Send(alice, ad, msg)
		pt, _ := arcad.Receive(bob, ad, ct)
		_ = pt

		msgSize += len(ct)
		//maxState = max(maxState, alice.Size())
		//maxState = max(maxState, bob.Size())
	}

	for i := 0; i < n/2; i++ {
		ct, _ := arcad.Send(bob, ad, msg)
		pt, _ := arcad.Receive(alice, ad, ct)
		_ = pt

		msgSize += len(ct)
		//maxState = max(maxState, alice.Size())
		//maxState = max(maxState, bob.Size())
	}

	return msgSize, maxState
}

func size_def(arcad *dv.ARCAD, n int) (int, int) {
	alice, bob, _ := arcad.Init()

	msgSize := 0
	maxState := 0

	var cts [1000][]byte
	for i := 0; i < n/2; i++ {
		ct, _ := arcad.Send(alice, ad, msg)
		cts[i] = ct

		msgSize += len(ct)
		//maxState = max(maxState, alice.Size())
	}

	for i := 0; i < n/2; i++ {
		ct, _ := arcad.Send(bob, ad, msg)
		pt, _ := arcad.Receive(alice, ad, ct)
		_ = pt

		msgSize += len(ct)
		//maxState = max(maxState, alice.Size())
		//maxState = max(maxState, bob.Size())
	}

	for i := 0; i < n/2; i++ {
		pt, _ := arcad.Receive(bob, ad, cts[i])
		_ = pt

		//maxState = max(maxState, bob.Size())
	}

	return msgSize, maxState
}

func main() {
	msg := make([]int, 10)

	s := ""
	for i, n := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900} {
		msg[i], _ = size_alternating(lite, n)
		s += fmt.Sprintf("(%d,%.2f)", n, float32(msg[i])/1000)
	}
	fmt.Println("Total Message Size (ALT)\n", s)

	s = ""
	for i, n := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900} {
		msg[i], _ = size_unidirectional(lite, n)
		s += fmt.Sprintf("(%d,%.2f)", n, float32(msg[i])/1000)
	}
	fmt.Println("Total Message Size (UNI)\n", s)

	s = ""
	for i, n := range []int{50, 100, 200, 300, 400, 500, 600, 700, 800, 900} {
		msg[i], _ = size_def(lite, n)
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
