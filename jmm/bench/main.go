// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package main

import (
	"crypto/elliptic"

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

func main() {
	time(time_def)
}
