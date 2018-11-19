// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package secmsg

import (
	"crypto/sha256"
	"encoding/json"
	"strconv"

	"github.com/pkg/errors"
	"github.com/qantik/ratcheted/primitives"
	"github.com/qantik/ratcheted/primitives/signature"
)

type SecMsg struct {
	hku *hkuPKE
	kus *kuSig
	sig signature.Signature
}

type User struct {
	ek, dk       []byte
	vkUpd, skUpd []byte
	vkEph, skEph []byte
	vk           [][]byte

	s, sAck, r int

	trace []byte
	trans [][]byte
}

type message struct {
	Msg, SkEph []byte
}

type ciphertext struct {
	C []byte

	VkEph []byte
	Upd   []byte
	R     int

	SigUpd, SigEph []byte
}

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

func (s SecMsg) Send(user *User, msg []byte) ([]byte, error) {
	vkEph1, skEph1, err := s.sig.Generate()
	if err != nil {
		return nil, errors.Wrap(err, "unable to generate ots keys")
	}
	//fmt.Println(primitives.Digest(sha256.New(), vkEph1), primitives.Digest(sha256.New(), skEph1))
	vkEph2, skEph2, err := s.sig.Generate()
	if err != nil {
		return nil, errors.Wrap(err, "unable to generate ots keys")
	}

	// encryption
	m, err := json.Marshal(&message{Msg: msg, SkEph: skEph1})
	if err != nil {
		return nil, errors.Wrap(err, "unable to marshal message")
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
	//fmt.Println("sign", primitives.Digest(sha256.New(), user.skEph))
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
	//fmt.Println("snd", h)

	c, err = json.Marshal(&ciphertext{
		C: c, Upd: upd, VkEph: vkEph2, R: user.r,
		SigUpd: sigUpd, SigEph: sigEph,
	})
	if err != nil {
		return nil, errors.Wrap(err, "unable to marshal ciphertext")
	}
	return c, nil
}

func (s SecMsg) Receive(user *User, ct []byte) ([]byte, error) {
	var c ciphertext
	if err := json.Unmarshal(ct, &c); err != nil {
		return nil, errors.Wrap(err, "unable to unmarshal ciphertext")
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
	//fmt.Println("rece", primitives.Digest(sha256.New(), vk))
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
	if err := json.Unmarshal(m, &msg); err != nil {
		return nil, errors.Wrap(err, "unable to unmarshal message")
	}

	user.ek = ek
	user.dk = dk
	user.vkUpd = vkUpd
	user.vkEph = c.VkEph
	user.skEph = msg.SkEph
	user.sAck = c.R
	user.r++
	user.trace = primitives.Digest(sha256.New(), user.trace, data)
	//fmt.Println("rec", user.trace)

	return msg.Msg, nil
}
