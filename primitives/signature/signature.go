// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

// Package signature bundles various digital signature schemes.
//
// The following schemes are implemeted:
//  - Lamport one-time signature
//  - ECDSA
//  - Bellare-Miner forward-secure signature
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

// ForwardSignature defines a common interface for forward-secure digital signature schemes.
type ForwardSignature interface {
	Signature

	// Update performs a key evolution on a private key.
	Update(sk []byte) ([]byte, error)
}
