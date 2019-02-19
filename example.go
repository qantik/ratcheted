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
	aes   = encryption.NewAES()
)

func main() {
	arcad := dv.NewARCAD(ecdsa, ecies, aes)

	msg := []byte("ratchet")
	ad := []byte("ad")

	alice, bob, _ := arcad.Init()

	c, _ := arcad.Send(alice, ad, msg)
	r, _ := arcad.Receive(bob, ad, c)

	fmt.Printf("Sent:\t\t%s\n", msg)
	fmt.Printf("Received:\t%s\n", r)
}
