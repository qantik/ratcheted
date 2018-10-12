// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

// Package sch implements the secure channel (SCh) protocol specified by Joseph Jaeger
// and Igors Stepanovs in their paper Optimal Channel Security Against Fine-Grained
// State Compromise: The Safety of Messaging (https://eprint.iacr.org/2018/553) first
// published at CRYPTO-2018. The scheme relies on novel cryptgraphic primitives like
// a key-updatable digital signature scheme and a key-updatable public-key encryption
// scheme.
package sch

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"

	"github.com/qantik/ratcheted/primitives/hibe"
	"github.com/qantik/ratcheted/primitives/signature"
)

const hashingKeySize = 16 // size of the hashing key in bytes.

// ErrOutOfSync means that one of the parties is working with out-of-order data.
// This can happen when a sent sequence of messages arrives in a different order
// at the receiver.
var ErrOutOfSync = errors.New("parties are out-of-sync")

type ErrSignature struct{ error }

func (e ErrSignature) Error() string { return e.Error() }

// SCh designates the secure channel protocol defined by a ku-DSS scheme and a ku-PKE scheme.
type SCh struct {
	kuDSS *kuDSS
	kuPKE *kuPKE
}

// User designates a participant in the protocol that can both send and receive
// messages. It has to be passed as an argument to both the send and receive routines.
type User struct {
	vk, sk []byte   // vk and sk are the kuDSS public/private key pair.
	ek     []byte   // ek is the kuPKE public key.
	dk     [][]byte // dk is an array of kuPKE private keys.
	hk     []byte   // hk is the hashing key.

	tau []byte   // tau is the latest hash ciphertext.
	t   [][]byte // t is the communication transcript.

	s, r, ack int // s, r and ack are the send, receive and acknowledge counters.
}

// Message bundles the ciphertext, the signature and auxiliary update data.
type Message struct {
	C   []byte // C is the ciphertext.
	Sig []byte // Sig is the message signature.
	Aux []byte // Aux contains auxiliary data that signed but not encrypted.
}

// auxiliary bundles signed auxiliary data that is sent alongside a ciphertext.
type auxiliary struct {
	VK, EK, AD, Tau, T []byte
	S, R               int
}

// NewSCh returns a fresh secure channel instance.
func NewSCh() *SCh {
	return &SCh{
		kuDSS: &kuDSS{signature: signature.NewBellare()},
		kuPKE: &kuPKE{hibe: hibe.NewGentry()},
	}
}

// Init creates and returns two User objects which can communicate with each other.
func (s SCh) Init() (*User, *User, error) {
	vkb, ska, err := s.kuDSS.generate()
	if err != nil {
		return nil, nil, err
	}
	vka, skb, err := s.kuDSS.generate()
	if err != nil {
		return nil, nil, err
	}
	eka, dkb, err := s.kuPKE.generate()
	if err != nil {
		return nil, nil, err
	}
	ekb, dka, err := s.kuPKE.generate()
	if err != nil {
		return nil, nil, err
	}
	var hk [hashingKeySize]byte
	if _, err := rand.Read(hk[:]); err != nil {
		return nil, nil, err
	}

	ua := &User{
		vk: vka, sk: ska,
		ek: eka, dk: [][]byte{dka},
		hk:  hk[:],
		tau: nil, t: [][]byte{nil},
		s: 0, r: 0, ack: 0,
	}
	ub := &User{
		vk: vkb, sk: skb,
		ek: ekb, dk: [][]byte{dkb},
		hk:  hk[:],
		tau: nil, t: [][]byte{nil},
		s: 0, r: 0, ack: 0,
	}
	return ua, ub, nil
}

func (s SCh) Send(user *User, ad, msg []byte) ([]byte, error) {
	user.s += 1

	vks, sks, err := s.kuDSS.generate()
	if err != nil {
		return nil, err
	}
	eks, dks, err := s.kuPKE.generate()
	if err != nil {
		return nil, err
	}
	user.dk = append(user.dk, dks)

	aux := auxiliary{
		VK: vks, EK: eks,
		AD:  ad,
		Tau: user.tau, T: user.t[user.s-1],
		S: user.s, R: user.r,
	}
	l, err := json.Marshal(&aux)
	if err != nil {
		return nil, err
	}

	// Encrypt message and update kuPKE public key.
	uek := user.ek
	for i := user.ack + 1; i < user.s; i++ {
		uek, err = s.kuPKE.updatePublicKey(uek, user.t[i])
		if err != nil {
			return nil, err
		}
	}
	c, err := s.kuPKE.encrypt(uek, msg)
	if err != nil {
		return nil, err
	}

	// Sign and marshal message.
	sig, err := s.kuDSS.sign(user.sk, append(c, l...))
	if err != nil {
		return nil, &ErrSignature{err}
	}
	m, err := json.Marshal(&Message{C: c, Sig: sig, Aux: l})
	if err != nil {
		return nil, err
	}

	sha := sha256.New()
	sha.Write(append(user.hk, m...))
	user.t = append(user.t, sha.Sum(nil))
	user.sk = sks

	return m, nil
}

func (s SCh) Receive(user *User, ad, m []byte) ([]byte, error) {
	var msg Message
	if err := json.Unmarshal(m, &msg); err != nil {
		return nil, err
	}
	var aux auxiliary
	if err := json.Unmarshal(msg.Aux, &aux); err != nil {
		return nil, err
	}
	if aux.S != user.r+1 || !bytes.Equal(aux.Tau, user.t[aux.R]) || !bytes.Equal(aux.T, user.tau) {
		return nil, ErrOutOfSync
	}

	uvk := user.vk
	for i := user.ack + 1; i <= aux.R; i++ {
		uvk, _ = s.kuDSS.updatePublicKey(uvk, user.t[i])
	}
	if err := s.kuDSS.verify(uvk, append(msg.C, msg.Aux...), msg.Sig); err != nil {
		return nil, err
	}

	user.r += 1
	user.ack = aux.R

	// Decrypt ciphertext and update kuPKE private key.
	pt, err := s.kuPKE.decrypt(user.dk[user.ack], msg.C)
	if err != nil {
		return nil, err
	}

	// Delete outdated data.
	for i := 0; i < user.ack; i++ {
		user.t[i] = nil
		user.dk[i] = nil
	}

	sha := sha256.New()
	sha.Write(append(user.hk, m...))
	user.tau = sha.Sum(nil)

	sks, err := s.kuDSS.updatePrivateKey(user.sk, user.tau)
	if err != nil {
		return nil, err
	}
	for i := user.ack; i <= user.s; i++ {
		user.dk[i], err = s.kuPKE.updatePrivateKey(user.dk[i], user.tau)
		if err != nil {
			return nil, err
		}
	}
	user.sk = sks

	user.vk = aux.VK
	user.ek = aux.EK

	return pt, nil
}
