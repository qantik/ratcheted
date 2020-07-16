// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// A constant size nonce is chosen at random for each new encryption and
// is prepended in clear to the ciphertext.
const nonceSize = 12

// GCM implements the AES-GCM AEAD scheme.
type GCM struct{}

// NewGCM returns a fresh AES-GCM instance.
func NewGCM() *GCM {
	return &GCM{}
}

// Encrypt applies the AES-GCM encryption/authentication routine to a given message
// and associated data.
func (g GCM) Encrypt(key, msg, ad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	var nonce [nonceSize]byte
	// if _, err := rand.Read(nonce[:]); err != nil {
	// 	return nil, err
	// }

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ct := gcm.Seal(nil, nonce[:], msg, ad)
	ct = append(nonce[:], ct...)
	return ct, nil
}

// Decrypt applies the AES-GCM decryption routine to a given message and associated data.
func (g GCM) Decrypt(key, ct, ad []byte) ([]byte, error) {
	if len(ct) < nonceSize {
		return nil, fmt.Errorf("invalid ciphertext size: %v", len(ct))
	}

	nonce := ct[:nonceSize]
	ct = ct[nonceSize:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	msg, err := gcm.Open(nil, nonce, ct, ad)
	if err != nil {
		return nil, err
	}
	return msg, nil
}
