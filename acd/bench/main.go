// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package main

import (
	"crypto/elliptic"

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

func main() {
	time(dr, time_alt)
	size(dr, size_alt)
}
