// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package main

import (
	"crypto/elliptic"

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

func main() {
	time(time_alt)
	size(size_alt)
}
