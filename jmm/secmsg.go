// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

// Package jmm implements the secure messaging protocol specified by Daniel Jost,
// Ueli Maurer and Marta Mularczyk in their paper Efficient Ratcheting: Almost-Optimal
// Guarantees for Secure Messaging (https://eprint.iacr.org/2018/954). The scheme
// relies on a novel healable key-updating public key encryption scheme, a key-updatable
// signature scheme and an ordinary one-time signature.
package jmm

import (
	"crypto/elliptic"
	"crypto/sha256"
	"strconv"

	"github.com/alecthomas/binary"

	"github.com/pkg/errors"

	"github.com/qantik/ratcheted/primitives"
	"github.com/qantik/ratcheted/primitives/encryption"
	"github.com/qantik/ratcheted/primitives/signature"
)

// SecMsg designates a secure messaging protocol instance.
type SecMsg struct {
	hku *hkuPKE             // hku is healable key-updatable public-key encryption scheme.
	kus *kuSig              // kus is the key-updatable signature scheme.
	sig signature.Signature // sig is a plain ots signature scheme.
}

// User designates a participant in the protocol that can both send and receive
// messages. It has to be passed as an argument to both the send and receive routines.
type User struct {
	ek, dk       []byte   // ek, dk are the hku-PKE public/private keys.
	vkUpd, skUpd []byte   // vkUpd, skUpd are the kus public/private keys.
	vkEph, skEph []byte   // vkEph, skEph are the ots public/private keys.
	vk           [][]byte // vk is an array ots public keys used for asynchronous traffic.

	// s, r are the number of sent (s), received (r) messages. sAck is the counterpart's
	// send epoch of the last received message.
	s, sAck, r int

	trace []byte   // trace is the chain hash of all received ciphertexts.
	trans [][]byte // trans is an array of all hashed ciphertexts (transcript).
}

// message groups the actual plaintext the ephemeral ots private key for encryption.
type message struct {
	Msg, SkEph []byte
}

// ciphertext group the actual ciphertext and auxiliary information for authentication.
type ciphertext struct {
	C []byte

	VkEph []byte
	Upd   []byte
	R     int

	SigUpd, SigEph []byte
}

// NewSecMsg returns a fresh secure messaging instance for a given public-key
// encryption scheme and a digital signature scheme.
func NewSecMsg(encryption encryption.Asymmetric, signature signature.Signature) *SecMsg {
	return &SecMsg{
		hku: &hkuPKE{pke: encryption, sku: &skuPKE{elliptic.P256()}},
		kus: &kuSig{signature},
		sig: signature,
	}
}

// Init creates and returns two User objects which can communicate with each other.
// Note, that in case of an error during a send or receiver operation both user states
// are considered corrupt thus requiring a fresh protocol initialization in order to
// resume communicating.
func (s SecMsg) Init() (*User, *User, error) {
	// create hku-pke key pairs
	eka, dka, err := s.hku.generate()
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to generate hku-PKE keys")
	}
	ekb, dkb, err := s.hku.generate()
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to generate hku-PKE keys")
	}

	// create ku-Sig key pairs
	vkUpda, skUpda, err := s.kus.generate()
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to generate ku-Sig keys")
	}
	vkUpdb, skUpdb, err := s.kus.generate()
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to generate ku-Sig keys")
	}

	// create ots keys pairs
	vkEpha, skEpha, err := s.sig.Generate()
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to generate ots keys")
	}
	vkEphb, skEphb, err := s.sig.Generate()
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to generate ots keys")
	}

	alice := &User{
		ek: ekb, dk: dka,
		vkUpd: vkUpdb, skUpd: skUpda,
		vkEph: vkEphb, skEph: skEpha, vk: [][]byte{},
		s: 0, sAck: 0, r: 0,
		trace: []byte{}, trans: [][]byte{[]byte{}},
	}
	bob := &User{
		ek: eka, dk: dkb,
		vkUpd: vkUpda, skUpd: skUpdb,
		vkEph: vkEpha, skEph: skEphb, vk: [][]byte{},
		s: 0, sAck: 0, r: 0,
		trace: []byte{}, trans: [][]byte{[]byte{}},
	}
	return alice, bob, nil
}

// Send encrypts and signs a given plaintext. It further advances the sender state
// one step forward (ratchet). The function returns a message object that contains
// the ciphertext and auxiliary authenticated data.
func (s SecMsg) Send(user *User, msg []byte) ([]byte, error) {
	vkEph1, skEph1, err := s.sig.Generate()
	if err != nil {
		return nil, errors.Wrap(err, "unable to generate ots keys")
	}
	vkEph2, skEph2, err := s.sig.Generate()
	if err != nil {
		return nil, errors.Wrap(err, "unable to generate ots keys")
	}

	// encryption
	m, err := binary.Marshal(&message{Msg: msg, SkEph: skEph1})
	if err != nil {
		return nil, errors.Wrap(err, "unable to encode message")
	}
	dk, upd, err := s.hku.updateDK(user.dk)
	if err != nil {
		return nil, errors.Wrap(err, "unable to update hku-PKE private key")
	}
	ek, c, err := s.hku.encrypt(user.ek, m, nil)
	if err != nil {
		return nil, errors.Wrap(err, "unable to hku-PKE encrypt message")
	}

	// signature
	data := primitives.Digest(sha256.New(), c, upd, vkEph2, []byte(strconv.Itoa(user.r)))
	skUpd, sigUpd, err := s.kus.sign(user.skUpd, append(data, user.trace...))
	if err != nil {
		return nil, errors.Wrap(err, "unable to ku-Sig sign ciphertext")
	}
	sigEph, err := s.sig.Sign(user.skEph, append(data, user.trace...))
	if err != nil {
		return nil, errors.Wrap(err, "unable to ots sign ciphertext")
	}

	// update user state
	user.s++
	user.ek = ek
	user.dk = dk
	user.skUpd = skUpd
	user.skEph = skEph2
	user.vk = append(user.vk, vkEph1)

	h := primitives.Digest(sha256.New(), user.trans[user.s-1], data)
	user.trans = append(user.trans, h)

	c, err = binary.Marshal(&ciphertext{
		C: c, Upd: upd, VkEph: vkEph2, R: user.r,
		SigUpd: sigUpd, SigEph: sigEph,
	})
	if err != nil {
		return nil, errors.Wrap(err, "unable to encode ciphertext")
	}
	return c, nil
}

// Receive decrypts a given ciphertext holding the plaintext and the ephemeral ots
// private key. A receive operation advances the receiver state of a user one step
// forward (ratchet) using the authenticated data sent along the ciphertext.
func (s SecMsg) Receive(user *User, ct []byte) ([]byte, error) {
	var c ciphertext
	if err := binary.Unmarshal(ct, &c); err != nil {
		return nil, errors.Wrap(err, "unable to decode ciphertext")
	}

	if c.R < user.sAck || c.R > user.s {
		return nil, errors.New("user are out-of-sync")
	}

	var vk []byte
	if c.R > user.sAck {
		vk = user.vk[c.R-1]
	} else {
		vk = user.vkEph
	}

	// verify signatures
	data := primitives.Digest(
		sha256.New(),
		c.C, c.Upd, c.VkEph, []byte(strconv.Itoa(c.R)),
	)
	if err := s.sig.Verify(vk, append(data, user.trans[c.R]...), c.SigEph); err != nil {
		return nil, errors.Wrap(err, "unable to verify ots signature")
	}
	vkUpd, err := s.kus.verify(user.vkUpd, append(data, user.trans[c.R]...), c.SigUpd)
	if err != nil {
		return nil, errors.Wrap(err, "unable to verify ku-Sig signature")
	}

	// decrypt ciphertext and update user state
	ek, err := s.hku.updateEK(user.ek, c.Upd)
	if err != nil {
		return nil, errors.Wrap(err, "unable to update hku-PKE public key")
	}
	dk, m, err := s.hku.decrypt(user.dk, c.C, nil)
	if err != nil {
		return nil, errors.Wrap(err, "unable to hku-PKE decrypt ciphertext")
	}
	var msg message
	if err := binary.Unmarshal(m, &msg); err != nil {
		return nil, errors.Wrap(err, "unable to decode message")
	}

	user.ek = ek
	user.dk = dk
	user.vkUpd = vkUpd
	user.vkEph = c.VkEph
	user.skEph = msg.SkEph
	user.sAck = c.R
	user.r++
	user.trace = primitives.Digest(sha256.New(), user.trace, data)

	return msg.Msg, nil
}

// Size returns the size (in bytes) of the user state.
func (u User) Size() int {
	size := 0
	for _, b := range u.vk {
		size += len(b)
	}
	for _, b := range u.trans {
		size += len(b)
	}
	return size + len(u.ek) + len(u.dk) + len(u.vkUpd) +
		len(u.skUpd) + len(u.vkEph) + len(u.skEph) + len(u.trace)
}
