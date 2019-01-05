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

	"github.com/pkg/errors"

	"github.com/qantik/ratcheted/primitives"
	"github.com/qantik/ratcheted/primitives/hibe"
	"github.com/qantik/ratcheted/primitives/signature"
)

const hashingKeySize = 16 // size of the hashing key in bytes.

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

// message bundles the ciphertext, the signature and auxiliary update data and is the object
// sent from one user to another.
type message struct {
	C   []byte // C is the ciphertext.
	Sig []byte // Sig is the message signature.

	Aux *aux   // Aux contains auxiliary data that signed but not encrypted.
	L   []byte // L is the marshalled auxiliary data.
}

// aux bundles signed auxiliary data that is sent alongside a ciphertext.
type aux struct {
	Vk, Ek, Ad, Tau, T []byte
	S, R               int
}

// NewSCh returns a fresh secure channel instance for a given forward-secure signature
// scheme and hierarchical identity-based encryption protocol.
func NewSCh(signature signature.ForwardSignature, hibe hibe.HIBE) *SCh {
	return &SCh{kuDSS: &kuDSS{signature: signature}, kuPKE: &kuPKE{hibe: hibe}}
}

var sEnc = 0
var sDec = 0
var sUpPk = 0
var sUpSk = 0

var pEnc = 0
var pDec = 0
var pUpPk = 0
var pUpSk = 0

// Init creates and returns two User objects which can communicate with each other.
// Note, that in case of an error during a send or receiver operation both user states
// are considered corrupt thus requiring a fresh protocol initialization in order to
// resume communicating.
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
		vk: vka, sk: ska, ek: eka, dk: [][]byte{dka}, hk: hk[:],
		tau: nil, t: [][]byte{nil},
		s: 0, r: 0, ack: 0,
	}
	ub := &User{
		vk: vkb, sk: skb, ek: ekb, dk: [][]byte{dkb}, hk: hk[:],
		tau: nil, t: [][]byte{nil},
		s: 0, r: 0, ack: 0,
	}

	pEnc, pDec, pUpPk, pUpSk = 0, 0, 0, 0
	sEnc, sDec, sUpPk, sUpSk = 0, 0, 0, 0

	return ua, ub, nil
}

// Send encrypts and signs a given plaintext and associated data. It further advances
// the sender state one step forward (ratchet). The function returns a message object
// that contains the ciphertext, auxiliary data and a signature.
func (s SCh) Send(user *User, ad, pt []byte) ([]byte, error) {
	user.s += 1

	vks, sks, err := s.kuDSS.generate()
	if err != nil {
		return nil, errors.Wrap(err, "unable to generate ku-dss key pair")
	}
	eks, dks, err := s.kuPKE.generate()
	if err != nil {
		return nil, errors.Wrap(err, "unable to generate ku-pke key pair")
	}
	user.dk = append(user.dk, dks)

	// Auxiliary data is both included in both marshalled and unmarshalled form in the
	// message sent such that the receiver only has to perform a single unmarshal operation.
	aux := &aux{
		Vk: vks, Ek: eks,
		Ad: ad, Tau: user.tau, T: user.t[user.s-1],
		S: user.s, R: user.r,
	}
	l, err := primitives.Encode(&aux)
	if err != nil {
		return nil, errors.Wrap(err, "unable to marshal auxiliary data")
	}

	uek := user.ek
	//fmt.Println("upPK", user.ack+1, user.s, user.s-(user.ack+1))
	for i := user.ack + 1; i < user.s; i++ {
		pUpPk++
		uek, err = s.kuPKE.updatePublicKey(uek, user.t[i])
		if err != nil {
			return nil, errors.Wrap(err, "unable to update ku-pke public key")
		}
	}
	c, err := s.kuPKE.encrypt(uek, pt)
	pEnc++
	if err != nil {
		return nil, errors.Wrap(err, "unable to encrypt message")
	}

	// Sign the ciphertext and the marshalled auxiliary data before
	// marshalling the resulting object.
	sig, err := s.kuDSS.sign(user.sk, append(c, l...))
	sEnc++
	if err != nil {
		return nil, errors.Wrap(err, "unable to sign message")
	}
	//fmt.Println(len(c), len(sig), len(vks), len(eks))
	msg, err := primitives.Encode(&message{C: c, Sig: sig, Aux: aux, L: l})
	if err != nil {
		return nil, errors.Wrap(err, "unable to decode message")
	}

	user.t = append(user.t, primitives.Digest(sha256.New(), user.hk, msg))
	user.sk = sks

	return msg, nil
}

// Receive decrypts a given message consisting of the actual ciphertext, signed auxiliary
// data and a signature. A receive operation advances the receiver state of a user one
// step forward (ratchet). The function returns a decrypted plaintext.
func (s SCh) Receive(user *User, ad, ct []byte) ([]byte, error) {
	var msg message
	if err := primitives.Decode(ct, &msg); err != nil {
		return nil, errors.Wrap(err, "unable to decode message")
	}

	// Check whether users are still synchronized. The following three properties have to hold:
	//   1. Sender sent counter must always be exactly be equal to receiver received counter + 1.
	//   2. Sender and receiver transcripts must always match on the latest entries.
	//   3. Associated data in the message must equal the local receiver ad.
	if msg.Aux.S != user.r+1 {
		return nil, errors.New("sent/receive counters are out-of-sync")
	} else if !bytes.Equal(msg.Aux.Tau, user.t[msg.Aux.R]) || !bytes.Equal(msg.Aux.T, user.tau) {
		return nil, errors.New("sender/receiver transcripts are out-of-sync")
	} else if !bytes.Equal(msg.Aux.Ad, ad) {
		return nil, errors.New("local and received associated data does not match")
	}

	uvk := user.vk
	//fmt.Println("upVK", user.ack+1, msg.Aux.R)
	for i := user.ack + 1; i <= msg.Aux.R; i++ {
		sUpPk++
		uvk, _ = s.kuDSS.updatePublicKey(uvk, user.t[i])
	}
	sDec++
	if err := s.kuDSS.verify(uvk, append(msg.C, msg.L...), msg.Sig); err != nil {
		return nil, errors.Wrap(err, "unable to verify signature")
	}

	user.r += 1
	user.ack = msg.Aux.R

	pDec++
	pt, err := s.kuPKE.decrypt(user.dk[user.ack], msg.C)
	if err != nil {
		return nil, errors.Wrap(err, "unable to decrypt ciphertext")
	}

	// Delete outdated data. Data is considered outdated once a user has completed a
	// successful round-trip cycle (send and receive).
	for i := 0; i < user.ack; i++ {
		user.t[i] = nil
		user.dk[i] = nil
	}

	user.tau = primitives.Digest(sha256.New(), user.hk, ct)

	sUpSk++
	sks, err := s.kuDSS.updatePrivateKey(user.sk, user.tau)
	if err != nil {
		return nil, errors.Wrap(err, "unable to update ku-dss private key")
	}
	//fmt.Println("upDK", user.ack, user.s)
	for i := user.ack; i <= user.s; i++ {
		pUpSk++
		user.dk[i], err = s.kuPKE.updatePrivateKey(user.dk[i], user.tau)
		if err != nil {
			return nil, errors.Wrap(err, "unable to udpate ku-pke private key")
		}
	}
	user.sk = sks
	user.vk = msg.Aux.Vk
	user.ek = msg.Aux.Ek

	return pt, nil
}

// size returns the size of a user object in bytes.
func (u User) size() int {
	total := 12 + len(u.vk) + len(u.ek) + len(u.sk) + len(u.hk) + len(u.tau)
	for _, d := range u.dk {
		total += len(d)
	}
	for _, t := range u.t {
		total += len(t)
	}
	return total
}
