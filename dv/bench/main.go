// (c) 2020 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

// Runtime, message size and state size benchmarks for the dv protocol.
package main

import (
	"crypto/elliptic"

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

	flag = 250

	arcad  = dv.NewARCAD(ecdsa, ecies, aes)
	lite   = dv.NewLiteARCAD(gcm, aes)
	hybrid = dv.NewHybridARCAD(ecdsa, ecies, aes, gcm, flag)
	block  = dv.NewBlockchainARCAD(hybrid)
	sarcad = dv.NewSARCAD(gcm, aes, true)
)

var (
	msg = []byte("msg")
	ad  = []byte("ad")
)

func main() {
	time(arcad, time_alt)
}
