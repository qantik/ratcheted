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
	gcm   = encryption.NewGCM()

	flag = 100
)

func main() {
	arcad := dv.NewHybridARCAD(ecdsa, ecies, aes, gcm, flag)
	block := dv.NewBlockchainARCAD(arcad)

	msg := []byte("ratchet")
	ad := []byte("ad")

	alice, bob, _ := block.Init()

	c, _ := block.Send(alice, ad, msg)
	r, _ := block.Receive(bob, ad, c)

	fmt.Printf("Sent:\t\t%s\n", msg)
	fmt.Printf("Received:\t%s\n", r)
}
