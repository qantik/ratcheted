// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

// Package encryption bundles various symmetric and asymmetric encryption schemes.
package encryption

// Asymmetric defines a common interface for asymmetric encryption schemes.
type Asymmetric interface {
	// Generate creates a public/private key pair.
	Generate() (pk, sk []byte, err error)
	// Encrypt enciphers a message with a given public key.
	Encrypt(pk, msg []byte) ([]byte, error)
	// Decrypt deciphers a message with a given private key.
	Decrypt(sk, ct []byte) ([]byte, error)
}

// Authenticated defines a common interface for authenticated encryption schemes.
type Authenticated interface {
	// Encrypt enciphers and authenticates a message and authenticates the associated data.
	Encrypt(key, msg, ad []byte) ([]byte, error)
	// Decrypt deciphers and authenticates a ciphertext with associated data.
	Decrypt(key, ct, ad []byte) ([]byte, error)
}

// Encapsulation defines a common interface for key-encapsulation mechanisms.
type Encapsulation interface {
	// Generate creates a public/private key pair.
	Generate() (pk, sk []byte, err error)
	// Encapsulate generates and encapsulates a fresh symmetric key.
	Encapsulate(pk []byte) (k, c []byte, err error)
	// Decapsulate decapsulates a symmetric key from a ciphertext.
	Decapsulate(sk, ct []byte) ([]byte, error)
}
