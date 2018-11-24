// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package bark

import (
	"github.com/qantik/ratcheted/primitives"
	"github.com/qantik/ratcheted/primitives/encryption"
	"github.com/qantik/ratcheted/primitives/signature"
)

// signcryption implements the simple signcryption primitive outlined in the paper.
type signcryption struct {
	encryption encryption.Asymmetric
	signature  signature.Signature
}

// signcryptionBlock bundles the message and signature for easier encryption and decryption.
type signcryptionBlock struct {
	AD, Message, Signature []byte
}

// generateSignKeys creates a signature public/private key pair.
func (s signcryption) generateSignKeys() (sk, pk []byte, err error) {
	pk, sk, err = s.signature.Generate()
	return
}

// generateCipherKeys creates a encryption public/private key pair.
func (s signcryption) generateCipherKeys() (sk, pk []byte, err error) {
	pk, sk, err = s.encryption.Generate(nil)
	return
}

// signcrypt a message with associated data.
func (s signcryption) signcrypt(sks, pkr, ad, msg []byte) ([]byte, error) {
	sig, err := s.signature.Sign(sks, append(ad, msg...))
	if err != nil {
		return nil, err
	}

	block := signcryptionBlock{AD: ad, Message: msg, Signature: sig}
	//b, err := json.Marshal(&block)
	b, err := primitives.Encode(&block)
	if err != nil {
		return nil, err
	}

	ct, err := s.encryption.Encrypt(pkr, b, nil)
	if err != nil {
		return nil, err
	}
	return ct, nil
}

// unsigncrypt a ciphertext with associated data.
func (s signcryption) unsigncrypt(skr, pks, ad, ct []byte) ([]byte, error) {
	dec, err := s.encryption.Decrypt(pks, ct, nil)
	if err != nil {
		return nil, err
	}

	var b signcryptionBlock
	if err := primitives.Decode(dec, &b); err != nil {
		//if err := json.Unmarshal(dec, &b); err != nil {
		return nil, err
	}

	if err := s.signature.Verify(skr, append(b.AD, b.Message...), b.Signature); err != nil {
		return nil, err
	}
	return b.Message, nil
}
