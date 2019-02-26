// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package dv

// User bundles all ARCAD user states under a common interface.
type Uuser interface {
	//Size() int
}

// Protocol bundles all ARCAD protocol instances under a common interface.
type Protocol interface {
	Init() (alice, bob Uuser, err error)
	Send(user Uuser, ad, msg []byte) (ct []byte, err error)
	Receive(user Uuser, ad, ct []byte) (msg []byte, err error)
}
