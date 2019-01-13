// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

// Package dratch implements the double ratchet protocol specified by
// Joël Alwen, Sandro Coretti and Yevgeniy Dodis in their paper
// The Double Ratchet:  Security Notions, Proofs, and
// Modularization for the Signal Protocol (https://eprint.iacr.org/2018/1037.pdf).
// The scheme relies on novel cryptographic primitives like a forward-secure
// authenticated encryption scheme with associated data (FS-AEAD), a
// continuous key-agreement protocol (CKA) and a PRF-PRNG construction.
package dratch

import (
	"crypto/elliptic"
	"strconv"

	"github.com/pkg/errors"

	"github.com/qantik/ratcheted/primitives"
	"github.com/qantik/ratcheted/primitives/encryption"
	"github.com/qantik/ratcheted/primitives/signature"
)

const keySize = 16

// DRatch designates the the secure channel protocol defined by a
// FS-AEAD scheme, a CKA construction and a PRF-PRNG algorithm.
type DRatch struct {
	pp  *prfPRNG
	fsa *fsAEAD
	cka *cka

	// optional pke and dss schemes
	pke encryption.Asymmetric
	dss signature.Signature
}

// dratchCiphertext bundles ciphertext material.
type dratchCiphertext struct {
	I int    // I is the epoch of the sender.
	T []byte // T is the CKA message.

	C []byte // C is the actual ciphertext.
	S []byte // S is an optional signature.

	EK, VK []byte
}

// User designates a participant in the protocol that can both send and receive
// messages. It has to be passed as an argument to both the send and receive routines.
type User struct {
	Gamma []byte // Gamma is CKA state.
	T     []byte // T is the current CKA message.
	I     int    // I is the current user epoch.
	Root  []byte // Root is the current PRF-PRNG key.

	V map[int][]byte // V contains all FS-AEAD (send, receive) states.

	// optional pke and dss key maps
	ek, dk map[int][]byte
	vk, sk map[int][]byte

	name string
}

// NewDRatch returns a fresh double ratchet instance for a given AEAD scheme.
func NewDRatch(aead encryption.Authenticated,
	pke encryption.Asymmetric,
	dss signature.Signature) *DRatch {
	return &DRatch{
		pp:  &prfPRNG{},
		fsa: &fsAEAD{aead: aead, pp: &prfPRNG{}},
		cka: &cka{curve: elliptic.P256()},
		pke: pke, dss: dss,
	}
}

// Init intializes the double ratchet protocol and returns two user states.
func (d DRatch) Init() (alice, bob *User, err error) {
	root, err := d.pp.generate()
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to initialize prf-prng")
	}
	root, k, err := d.pp.up(keySize, root, nil)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to poll prf-prng")
	}

	_, va, err := d.fsa.generate(k)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to generate fs-aead state")
	}
	_, vb, err := d.fsa.generate(k)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to generate fs-aead state")
	}

	ga, gb, err := d.cka.generate()
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to generate cka states")
	}

	var eka, dka, vka, ska map[int][]byte
	var ekb, dkb, vkb, skb map[int][]byte

	if d.pke != nil && d.dss != nil {
		eka, dka, vka, ska, ekb, dkb, vkb, skb, err = d.genOpt()
		if err != nil {
			return nil, nil, errors.Wrap(err, "unable to create optional keys")
		}
	}

	alice = &User{
		Gamma: ga, T: nil, I: 0, V: map[int][]byte{0: va},
		ek: eka, dk: dka, vk: vka, sk: ska,
		name: "alice",
	}
	bob = &User{
		Gamma: gb, T: nil, I: 0, V: map[int][]byte{0: vb},
		ek: ekb, dk: dkb, vk: vkb, sk: skb,
		name: "bob",
	}
	return
}

// genOpt generates the sets of optional PKE and DSS key pairs.
func (d DRatch) genOpt() (eka, dka, vka, ska, ekb, dkb, vkb, skb map[int][]byte, err error) {
	eka, ekb = make(map[int][]byte), make(map[int][]byte)
	dka, dkb = make(map[int][]byte), make(map[int][]byte)
	vka, vkb = make(map[int][]byte), make(map[int][]byte)
	ska, skb = make(map[int][]byte), make(map[int][]byte)

	ek0, dk0, _ := d.pke.Generate(nil)
	ek1, dk1, _ := d.pke.Generate(nil)
	vk0, sk0, _ := d.dss.Generate()
	vk1, sk1, _ := d.dss.Generate()
	vk2, sk2, _ := d.dss.Generate()

	vka[0], dka[0] = vk0, dk0
	eka[1], ska[1] = ek1, sk1
	vka[1], dka[1] = vk1, dk1

	vkb[0], dkb[0] = vk0, dk0
	ekb[1], skb[1] = ek1, sk1
	vkb[1], dkb[1] = vk1, dk1

	ska[2], skb[2] = sk2, sk2
	vka[2], vkb[2] = vk2, vk2

	eka[0], ekb[0] = ek0, ek0
	ska[0], skb[0] = sk0, sk0

	return
}

// Send calls the double ratchet send routine for a given user and message.
func (d DRatch) Send(user *User, msg []byte) ([]byte, error) {
	if (user.name == "alice" && user.I%2 == 0) || (user.name == "bob" && user.I%2 == 1) {
		user.V[user.I-1] = nil

		user.I++
		gamma, t, i, err := d.cka.send(user.Gamma)
		if err != nil {
			return nil, errors.Wrap(err, "unable create cka message")
		}
		user.Gamma = gamma
		user.T = t

		root, k, err := d.pp.up(16, user.Root, i)
		if err != nil {
			return nil, errors.Wrap(err, "unable to poll prf-prng")
		}
		user.Root = root

		v, _, err := d.fsa.generate(k)
		if err != nil {
			return nil, errors.Wrap(err, "unable to create fresh fs-aead sender state")
		}
		user.V[user.I] = v

		if d.pke != nil && d.dss != nil {
			ek, dk, err := d.pke.Generate(nil)
			if err != nil {
				return nil, errors.Wrap(err, "unable to create fresh pke key pair")
			}
			vk, sk, err := d.dss.Generate()
			if err != nil {
				return nil, errors.Wrap(err, "unable to create fresh dss key pair")
			}
			user.ek[user.I+1], user.dk[user.I+1] = ek, dk
			user.vk[user.I+2], user.sk[user.I+2] = vk, sk
		}
	}
	var ad []byte
	if d.pke != nil && d.dss != nil {
		ad = primitives.Concat(
			[]byte(strconv.Itoa(user.I)),
			user.T,
			user.ek[user.I+1],
			user.vk[user.I+2],
		)
	} else {
		ad = primitives.Concat([]byte(strconv.Itoa(user.I)), user.T)
	}

	v, c, err := d.fsa.send(user.V[user.I], msg, ad)
	if err != nil {
		return nil, errors.Wrap(err, "unable to fs-aead encrypt message")
	}
	user.V[user.I] = v

	var ct []byte
	if d.pke != nil && d.dss != nil {
		c, err = d.pke.Encrypt(user.ek[user.I], c, nil)
		if err != nil {
			return nil, errors.Wrap(err, "unable to pke encrypt message")
		}
		s, err := d.dss.Sign(user.sk[user.I], append(ad, c...))
		if err != nil {
			return nil, errors.Wrap(err, "unable to dss sign message")
		}

		ct, err = primitives.Encode(&dratchCiphertext{
			I: user.I, T: user.T,
			C: c, S: s,
			EK: user.ek[user.I+1], VK: user.vk[user.I+2],
		})
		if err != nil {
			return nil, errors.Wrap(err, "unable to encode dratch ciphertext")
		}
	} else {
		ct, err = primitives.Encode(&dratchCiphertext{I: user.I, T: user.T, C: c})
		if err != nil {
			return nil, errors.Wrap(err, "unable to encode dratch ciphertext")
		}
	}
	return ct, nil
}

// Receive calls the double ratchet receive routine for a given user and ciphertext.
func (d DRatch) Receive(user *User, ct []byte) ([]byte, error) {
	var c dratchCiphertext
	if err := primitives.Decode(ct, &c); err != nil {
		return nil, errors.Wrap(err, "unable to decode dratch ciphertext")
	}

	var ad, cipher []byte
	if d.pke != nil && d.dss != nil {
		ad = primitives.Concat(
			[]byte(strconv.Itoa(c.I)),
			c.T,
			c.EK, c.VK,
		)
		if err := d.dss.Verify(user.vk[c.I], append(ad, c.C...), c.S); err != nil {
			return nil, errors.Wrap(err, "unable to verify dss signature")
		}

		cipher, _ = d.pke.Decrypt(user.dk[c.I], c.C, nil)
	} else {
		ad = append([]byte(strconv.Itoa(c.I)), c.T...)
		cipher = c.C
	}

	if (user.name == "alice" && c.I <= user.I && c.I%2 == 0) ||
		(user.name == "bob" && c.I <= user.I && c.I%2 == 1) {

		v, msg, err := d.fsa.receive(user.V[c.I], cipher, ad)
		if err != nil {
			return nil, errors.Wrap(err, "unable to fs-aead decrypt message")
		}
		user.V[c.I] = v

		return msg, nil
	} else if (user.name == "alice" && c.I == user.I+1 && user.I%2 == 1) ||
		(user.name == "bob" && c.I == user.I+1 && user.I%2 == 0) {
		user.V[c.I-2] = nil
		user.I++
		if d.pke != nil && d.dss != nil {
			user.sk[c.I-1], user.ek[c.I], user.vk[c.I+1] = nil, nil, nil
			user.ek[c.I+1], user.vk[c.I+2] = c.EK, c.VK
		}

		gamma, i, err := d.cka.receive(user.Gamma, c.T)
		if err != nil {
			return nil, errors.Wrap(err, "unable to receive cka message")
		}
		user.Gamma = gamma

		root, k, err := d.pp.up(16, user.Root, i)
		if err != nil {
			return nil, errors.Wrap(err, "unable to poll prf-prng")
		}
		user.Root = root

		_, v, err := d.fsa.generate(k)
		if err != nil {
			return nil, errors.Wrap(err, "unable to create fresh fs-aead receiver state")
		}
		user.V[c.I] = v

		v, msg, err := d.fsa.receive(user.V[c.I], cipher, ad)
		if err != nil {
			return nil, errors.Wrap(err, "unable to fs-aead decrypt message")
		}
		user.V[c.I] = v

		return msg, nil
	}
	return nil, errors.New("user epochs are out-of-sync")
}

// Size returns the size (in bytes) of a user state.
func (u User) Size() int {
	size := 0
	for _, a := range []map[int][]byte{u.V, u.ek, u.dk, u.vk, u.sk} {
		for _, b := range a {
			size += len(b)
		}
	}
	return size + len(u.Gamma) + len(u.T) + len(u.Root)
}
