// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

// Package signature bundles various digital signature schemes under a common
// interface.
//
// The following schemes are implemeted:
//  - Lamport one-time signature [Constructing digital signatures from a one-way function]
//  - ECDSA
//
package signature

// Signature defines a common interface to which signature schemes have to conform.
type Signature interface {
	// Generate creates a public/private key pair.
	Generate() (pk, sk []byte, err error)
	// Sign creates a signature for a given message.
	Sign(sk, msg []byte) ([]byte, error)
	// Verify checks the validity of a given signature.
	Verify(pk, msg, sig []byte) error
}
