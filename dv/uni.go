// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package dv

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"io"

	"github.com/pkg/errors"

	"github.com/qantik/ratcheted/primitives"
	"github.com/qantik/ratcheted/primitives/encryption"
	"github.com/qantik/ratcheted/primitives/signature"
)

// uniARCAD is the uniARCAD object handler.
type uniARCAD struct {
	sc *signcryption
}

// sender is the uniARCAD sender state.
type sender struct {
	SKS, PKR []byte // SKS, PKR are the signcryption encryption and signature keys.
}

// receiver is the uniARCAD receiver state.
type receiver struct {
	SKR, PKS []byte // SKR, PKS are the signcryption decryption and verification keys.
}

// uniBlock bundles the updated receiver state with a plaintext message.
type uniBlock struct {
	R, Message []byte
}

type uniCipher struct {
	C [][]byte
}

// NewUniARCAD returns a fresh uniARCAD instance for a given public-key encryption
// scheme and a digital signature scheme.
func NewUniARCAD(enc encryption.Asymmetric, sig signature.Signature) *uniARCAD {
	return &uniARCAD{sc: &signcryption{encryption: enc, signature: sig}}
}

// Init generates initialized the uniARCAD protocol, returning
// both a sender and receiver state.
func (u uniARCAD) Init() (s, r []byte, err error) {
	sks, skr, err := u.sc.generateSignKeys()
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to generate signcryption signature keys")
	}

	pks, pkr, err := u.sc.generateCipherKeys()
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to generate signcryption cipher keys")
	}

	s, err = primitives.Encode(sender{SKS: sks, PKR: pkr})
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to encode uni-bark sender")
	}
	r, err = primitives.Encode(receiver{SKR: skr, PKS: pks})
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to encode uni-bark receiver")
	}
	return
}

// Send invokes the uniARCAD send routine for a given sender state, associated data
// and a plaintext. Ratchet indicates whether the sender state is updated or not.
func (u uniARCAD) Send(states [][]byte, hk, ad, pt []byte) (upd, ct []byte, err error) {
	s := make([]sender, len(states))
	for i, st := range states {
		if err := primitives.Decode(st, &s[i]); err != nil {
			return nil, nil, errors.Wrap(err, "unable to decode uni-bark sender state")
		}
	}

	us, ur, err := u.Init()
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to create new uni-bark instance")
	}
	upd = us

	var kss [][]byte
	k := make([]byte, sessionKeySize)
	for i := 0; i < len(states); i++ {
		var ks [sessionKeySize]byte
		if _, err := rand.Read(ks[:]); err != nil {
			return nil, nil, err
		}
		kss = append(kss, ks[:])
	}

	for _, ks := range kss {
		k = xor(k, ks)
	}
	//fmt.Println("ggg", k)

	block, err := primitives.Encode(uniBlock{R: ur, Message: pt})
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to encode uni-bark message")
	}
	block = pad(block)

	cts := make([][]byte, len(states)+1)
	ads := make([][]byte, len(states)+1)

	cbc, _ := aes.NewCipher(k)

	c := make([]byte, aes.BlockSize+len(block))
	iv := c[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	//fmt.Println("iv", iv)

	mode := cipher.NewCBCEncrypter(cbc, iv)
	mode.CryptBlocks(c[aes.BlockSize:], block)

	//fmt.Println("s", c)
	cts[len(states)] = c
	ads[len(states)] = ad

	for i := len(states) - 1; i >= 0; i-- {
		ads[i] = primitives.Digest(hmac.New(sha256.New, hk), ads[i+1], cts[i+1])

		ct, err = u.sc.signcrypt(s[i].SKS, s[i].PKR, ads[i], kss[i])
		if err != nil {
			return nil, nil, errors.Wrap(err, "unable to signcrypt uni-bark message")
		}
		cts[i] = ct
	}
	//fmt.Println("******", cts)

	ct, err = primitives.Encode(uniCipher{C: cts})
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to encode uni-bark cipher")
	}

	return
}

// Receive invokes the uniARCAD receive routine for a given receiver state,
// associated data and a ciphertext.
func (u uniARCAD) Receive(states [][]byte, hk, ad, ct []byte) (upd, pt []byte, err error) {
	r := make([]receiver, len(states))
	for i, st := range states {
		if err := primitives.Decode(st, &r[i]); err != nil {
			return nil, nil, errors.Wrap(err, "unable to decode uni-bark sender state")
		}
	}

	var c uniCipher
	if err := primitives.Decode(ct, &c); err != nil {
		return nil, nil, errors.Wrap(err, "unable to decode uni-bark ciphertext")
	}

	k := make([]byte, sessionKeySize)

	ads := make([][]byte, len(states)+1)
	ads[len(states)] = ad

	for i := len(states) - 1; i >= 0; i-- {
		ads[i] = primitives.Digest(hmac.New(sha256.New, hk), ads[i+1], c.C[i+1])

		dec, err := u.sc.unsigncrypt(r[i].SKR, r[i].PKS, ads[i], c.C[i])
		if err != nil {
			return nil, nil, errors.Wrap(err, "unable to decrypt")
		}
		k = xor(k, dec)
	}

	//fmt.Println("hhh", k)

	cbc, _ := aes.NewCipher(k)
	//fmt.Println("r", c.C[len(states)])

	iv := c.C[len(states)][:aes.BlockSize]
	ciphertext := c.C[(len(states))][aes.BlockSize:]
	//fmt.Println("iv", iv)

	mode := cipher.NewCBCDecrypter(cbc, iv)
	mode.CryptBlocks(ciphertext, ciphertext)
	ciphertext, _ = unpad(ciphertext)

	var block uniBlock
	if err := primitives.Decode(ciphertext, &block); err != nil {
		return nil, nil, errors.Wrap(err, "unable to decode uni-bark message")
	}
	upd, pt = block.R, block.Message
	return
}

// xor computes the exclusive-or of two byte arrays.
// TODO: Refactor and rewrite xor into a robuster version.
func xor(a, b []byte) []byte {
	if a == nil {
		return b
	} else if b == nil {
		return a
	}

	c := make([]byte, len(a))
	for i := range a {
		c[i] = a[i] ^ b[i]
	}
	return c
}

func pad(src []byte) []byte {
	padding := aes.BlockSize - len(src)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func unpad(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])

	if unpadding > length {
		return nil, errors.New("unpad error. This could happen when incorrect encryption key is used")
	}

	return src[:(length - unpadding)], nil
}
