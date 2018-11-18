// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package secmsg

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
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
		S: -1, J: 0,
		Ue: [][]byte{}, Trace: []byte{},
	}
	s, err = json.Marshal(&sender)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to marshal hkuPKE sender state")
	}
	receiver := hkuReceiver{
		DkUpd: [][]byte{dkUpd}, DkEph: [][]byte{dkEph},
		R: -1, I: 0,
		Trace: []byte{},
	}
	r, err = json.Marshal(&receiver)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to marshal hkuPKE receiver state")
	}
	return
}

// encrypt enciphers a message with associated data and updates the sender state.
func (h hkuPKE) encrypt(sender, msg, ad []byte) (upd, ct []byte, err error) {
	var s hkuSender
	if err := json.Unmarshal(sender, &s); err != nil {
		return nil, nil, errors.Wrap(err, "unable to unmarshal hkuPKE sender state")
	}
	s.S++

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
	m, err := json.Marshal(&message)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to marshal message")
	}
	c, err := h.sku.encrypt(s.EkUpd, m)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to skuPKE encrypt message")
	}
	fmt.Println("sfasdf", len(c))
	c, err = h.pke.Encrypt(s.EkEph, c, ad)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to PKE encrypt ciphertext")
	}
	ct, err = json.Marshal(&hkuCiphertext{C: c, J: s.J})
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to marshal ciphertext")
	}

	// compute trace
	s.Trace = primitives.Digest(sha256.New(), s.Trace, c, []byte(strconv.Itoa(s.J)), ad)

	// update public keys
	fmt.Println(len(s.Ue), s.S)
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

	upd, err = json.Marshal(&s)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to marshal hku sender state")
	}
	return
}

// decrypt deciphers a ciphertext with given associated data and updates the
// receiver state.
func (h hkuPKE) decrypt(receiver, ct, ad []byte) (upd, msg []byte, err error) {
	var r hkuReceiver
	if err := json.Unmarshal(receiver, &r); err != nil {
		return nil, nil, errors.Wrap(err, "unable to unmarshal hkuPKE receiver state")
	}
	var ciphertext hkuCiphertext
	if err := json.Unmarshal(ct, &ciphertext); err != nil {
		return nil, nil, errors.Wrap(err, "unable to unmarshal ciphertext")
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
	if err := json.Unmarshal(m, &message); err != nil {
		return nil, nil, errors.Wrap(err, "unable to unmarshal message")
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

	upd, err = json.Marshal(&r)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to marshal hkuPKE receiver state")
	}
	return upd, message.Msg, nil
}
