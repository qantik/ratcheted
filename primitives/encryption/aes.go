// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package encryption

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

// aesKeySize designates the fixed 128-bit AES key size.
const aesKeySize = 16

// AES is the AES-CBC object handler.
type AES struct{}

// NewAES returns a fresh AES-CBC instance.
func NewAES() *AES {
	return &AES{}
}

// Generate creates a fresh 16-byte AES-CBC symmetric key. If seed is nil
// crypto.rand is used as the random stream.
func (a AES) Generate(seed []byte) ([]byte, error) {
	var reader io.Reader
	if seed == nil {
		reader = rand.Reader
	} else {
		reader = bytes.NewReader(seed)
	}

	k := make([]byte, aesKeySize)

	if _, err := io.ReadFull(reader, k); err != nil {
		return nil, err
	}
	return k, nil
}

// Encrypt invokes the AES-CBC encryption routine.
func (a AES) Encrypt(key, msg []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// The message has to be padded to be a multiple of the block size.
	padded := pad(msg)

	ct := make([]byte, aes.BlockSize+len(padded))
	iv := ct[:aes.BlockSize]
	// if _, err := rand.Read(iv); err != nil {
	// 	return nil, err
	// }

	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(ct[aes.BlockSize:], padded)

	return ct, nil
}

// Decrypt invokes the AES-CBC decryption routine.
func (a AES) Decrypt(key, ct []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := ct[:aes.BlockSize]
	ct = ct[aes.BlockSize:]

	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(ct, ct)

	return unpad(ct), nil
}

// pad a byte slice to a multiple of the AES block size.
func pad(src []byte) []byte {
	if len(src)%16 == 0 {
		return src
	}
	padding := aes.BlockSize - len(src)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

// unpad a byte slice.
func unpad(src []byte) []byte {
	if len(src)%16 == 0 {
		return src
	}
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}
