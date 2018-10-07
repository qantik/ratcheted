// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

// Package encryption bundles various symmetric and asymmetric encryption schemes.
package encryption

// Asymmetric defines a common interface to which asymmetric encryption schemes.
type Asymmetric interface {
	// Generate creates a public/private key pair.
	Generate() (pk, sk []byte, err error)
	// Encrypt enciphers a message with a given public key.
	Encrypt(pk, msg []byte) ([]byte, error)
	// Decrypt deciphers a message with a given private key.
	Decrypt(sk, ct []byte) ([]byte, error)
}
