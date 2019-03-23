// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

// Package dv contains the implementation of the ARCAD, hybrid-ARCAD
// and blockchain-ARCAD protocols by Durak and Vaudenay as specified
// in their papers 'Bidirectional Asynchronous Ratcheted Key Agreement
// without Key-Update Primitives' (eprint.iacr.org/2018/889.pdf) and TODO...
package dv

// User bundles all ARCAD user states under a common interface.
type User interface {
	Size() int
}

// Protocol bundles all ARCAD protocol instances under a common interface.
type Protocol interface {
	Init() (alice, bob User, err error)
	Send(user User, ad, msg []byte) (ct []byte, err error)
	Receive(user User, ad, ct []byte) (msg []byte, err error)
}
