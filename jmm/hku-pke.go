// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package jmm

import (
	"crypto/rand"
	"crypto/sha256"
	"strconv"

	"github.com/pkg/errors"

	"github.com/qantik/ratcheted/primitives"
	"github.com/qantik/ratcheted/primitives/encryption"
)

// hkuPKE implements the healable key-updating encryption scheme based on
// a public-key encryption scheme with associated data and a secretly key-updatable
// public-key encryptions scheme.
type hkuPKE struct {
	pke encryption.Asymmetric // pke is a PKE with associated data.
	sku *skuPKE               // sku is a secretly key-updatable PKE.
}

// hkuSender is the hkuPKE sender state.
type hkuSender struct {
	EkUpd []byte // EkUpd is the skuPKE public key.
	EkEph []byte // EkEph is the PKE public key.

	S int // S is the number of encrypted messages.
	J int // J is the number of times the sender state has been healed.

	Ue    [][]byte // Ue is an array of update information for the skuPKE.
	Trace []byte   // Trace is the chain hash of all ciphertexts.
}

// hkuReceiver is the hkuPKE receiver state.
type hkuReceiver struct {
	DkUpd [][]byte // DkUpd is an array of skuPKE private keys.
	DkEph [][]byte // DkEph is an array of PKE private keys.

	R int // R is the number of decrypted messages.
	I int // I is the number of times the receiver state has been healed.

	Trace []byte // Trace is the chain hash of all ciphertexts.
}

// hkuMessage bundles message material before encryption.
type hkuMessage struct {
	Msg []byte // Msg is the plaintext.
	Ud  []byte // Ud is skuPKE secret key update information.
	Z   []byte // Z is the randomness used to create a new PKE key pair.
}

// hkuCiphertext bundles ciphertext material that is sent over the channel.
type hkuCiphertext struct {
	C []byte // C is the actual ciphertext.
	J int    // J designates the healing period of the sender.
}

// hkuUpdInfo bundles update information upon a healing call from the receiver.
type hkuUpdInfo struct {
	EkUpd []byte // EkUpd is a fresh PKE public key.
	EkEph []byte // EkEph is a fresh sku-PKE public key.
	R     int    // R indicates after how many received message the healing applied.
}

// generate creates a fresh hkuPKE sender and receciver state.
func (h hkuPKE) generate() (s, r []byte, err error) {
	ekUpd, dkUpd, err := h.sku.generate()
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to create skuPKE states")
	}
	ekEph, dkEph, err := h.pke.Generate(nil)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to create PKE states")
	}

	sender := hkuSender{
		EkUpd: ekUpd, EkEph: ekEph,
		S: 0, J: 0,
		Ue: [][]byte{}, Trace: []byte{},
	}
	s, err = primitives.Encode(&sender)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to encode hkuPKE sender state")
	}
	receiver := hkuReceiver{
		DkUpd: [][]byte{dkUpd}, DkEph: [][]byte{dkEph},
		R: 0, I: 0,
		Trace: []byte{},
	}
	r, err = primitives.Encode(&receiver)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to encode hkuPKE receiver state")
	}
	return
}

// encrypt enciphers a message with associated data and updates the sender state.
func (h hkuPKE) encrypt(sender, msg, ad []byte) (upd, ct []byte, err error) {
	var s hkuSender
	if err := primitives.Decode(sender, &s); err != nil {
		return nil, nil, errors.Wrap(err, "unable to decode hkuPKE sender state")
	}

	// generate update information
	ue, ud, err := h.sku.updateGen()
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to generate skuPKE update information")
	}
	s.Ue = append(s.Ue, ue)

	// encrypt message and associated data
	z := make([]byte, 16)
	if _, err := rand.Read(z); err != nil {
		return nil, nil, errors.Wrap(err, "unable to sample randomness")
	}
	message := hkuMessage{Msg: msg, Ud: ud, Z: z}
	m, err := primitives.Encode(&message)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to encode message")
	}
	c, err := h.sku.encrypt(s.EkUpd, m)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to skuPKE encrypt message")
	}
	c, err = h.pke.Encrypt(s.EkEph, c, ad)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to PKE encrypt ciphertext")
	}
	ct, err = primitives.Encode(&hkuCiphertext{C: c, J: s.J})
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to encode ciphertext")
	}

	// compute trace
	s.Trace = primitives.Digest(sha256.New(), s.Trace, c, []byte(strconv.Itoa(s.J)), ad)

	// update public keys
	ekUpd, err := h.sku.updatePK(s.Ue[s.S], s.EkUpd)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to update skuPKE public key")
	}
	seed := primitives.Digest(sha256.New(), s.Trace, z)
	ekEph, _, err := h.pke.Generate(seed)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to create new PKE public key")
	}
	s.EkUpd = ekUpd
	s.EkEph = ekEph
	s.S++

	upd, err = primitives.Encode(&s)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to encode hku sender state")
	}
	return
}

// decrypt deciphers a ciphertext with given associated data and updates the
// receiver state.
func (h hkuPKE) decrypt(receiver, ct, ad []byte) (upd, msg []byte, err error) {
	var r hkuReceiver
	if err := primitives.Decode(receiver, &r); err != nil {
		return nil, nil, errors.Wrap(err, "unable to decode hkuPKE receiver state")
	}
	var ciphertext hkuCiphertext
	if err := primitives.Decode(ct, &ciphertext); err != nil {
		return nil, nil, errors.Wrap(err, "unable to decode ciphertext")
	}
	r.R++

	// decrypt ciphertext
	c, err := h.pke.Decrypt(r.DkEph[ciphertext.J], ciphertext.C, ad)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to PKE decrypt ciphertext")
	}
	m, err := h.sku.decrypt(r.DkUpd[ciphertext.J], c)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to skuPKE decrypt ciphertext")
	}
	var message hkuMessage
	if err := primitives.Decode(m, &message); err != nil {
		return nil, nil, errors.Wrap(err, "unable to decode message")
	}

	// compute trace
	r.Trace = primitives.Digest(
		sha256.New(),
		r.Trace, ciphertext.C, []byte(strconv.Itoa(ciphertext.J)), ad,
	)

	// update secret keys
	seed := primitives.Digest(sha256.New(), r.Trace, message.Z)
	_, dkEph, err := h.pke.Generate(seed)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to create new PKE private key")
	}
	for l := 0; l <= r.I; l++ {
		if l < ciphertext.J {
			r.DkUpd[l] = nil
			r.DkEph[l] = nil
		} else {
			r.DkEph[l] = dkEph
			r.DkUpd[l], err = h.sku.updateSK(message.Ud, r.DkUpd[l])
			if err != nil {
				return nil, nil, errors.Wrap(err, "unable to update skuPKE private key")
			}
		}
	}

	upd, err = primitives.Encode(&r)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to encode hkuPKE receiver state")
	}
	return upd, message.Msg, nil
}

// updateDK initiates a receiver healing that creates new key pairs.
func (h hkuPKE) updateDK(receiver []byte) (upd, inf []byte, err error) {
	var r hkuReceiver
	if err := primitives.Decode(receiver, &r); err != nil {
		return nil, nil, errors.Wrap(err, "unable to decode hkuPKE receiver state")
	}
	r.I++

	ekUpd, dkUpd, err := h.sku.generate()
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to create skuPKE states")
	}
	ekEph, dkEph, err := h.pke.Generate(nil)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to create PKE states")
	}
	r.DkUpd = append(r.DkUpd, dkUpd)
	r.DkEph = append(r.DkEph, dkEph)

	inf, err = primitives.Encode(&hkuUpdInfo{EkUpd: ekUpd, EkEph: ekEph, R: r.R})
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to encode update information")
	}
	upd, err = primitives.Encode(&r)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to encode hkuPKE receiver state")
	}
	return
}

// updateEK updates the sender state with fresh public keys with the given update info.
func (h hkuPKE) updateEK(sender, inf []byte) (upd []byte, err error) {
	var s hkuSender
	if err := primitives.Decode(sender, &s); err != nil {
		return nil, errors.Wrap(err, "unable to decode hkuPKE sender state")
	}
	var i hkuUpdInfo
	if err := primitives.Decode(inf, &i); err != nil {
		return nil, errors.Wrap(err, "unable to decode hkuPKE update info")
	}
	s.J++

	if i.R >= s.S {
		s.EkEph = i.EkEph
	}
	s.EkUpd = i.EkUpd

	for l := i.R; l < s.S; l++ {
		ek, err := h.sku.updatePK(s.Ue[l], s.EkUpd)
		if err != nil {
			return nil, errors.Wrap(err, "unable to update sku-PKE public key")
		}
		s.EkUpd = ek
	}
	upd, err = primitives.Encode(&s)
	if err != nil {
		return nil, errors.Wrap(err, "unable to encode hku sender state")
	}
	return
}
