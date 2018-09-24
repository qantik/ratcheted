// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package r1

type kuKEM interface {
	GenerateKeys() (pk, sk []byte)
	GenerateSecret(seed []byte) []byte
	GeneratePublicFromSecret(secret []byte) []byte

	UpdatePublic(public, ad []byte) []byte
	UpdateSecret(secret, ad []byte) []byte
	Encrypt(public []byte) (k, c []byte)
	Decrypt(secret, c []byte) []byte
}

type ots interface {
	GenerateKeys() (pk, sk []byte)
	Sign(sk, msg []byte) (sig []byte)
	Verify(pk, msg, sig []byte) bool
}
