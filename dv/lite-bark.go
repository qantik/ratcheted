package dv

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"strconv"

	"github.com/pkg/errors"

	"github.com/qantik/ratcheted/primitives"
)

// uni is a helper interface under which uniARCAD and lite-uniARCAD are unified.
type lite interface {
	Init() ([]byte, []byte, error)
	Send(state, ad, pt []byte, simple bool) ([]byte, []byte, error)
	Receive(state, ad, ct []byte) ([]byte, []byte, error)
}

// BARK implements the Bidirectional Asynchronous Key-Agreement protocol.
type liteBARK struct {
	uni lite
}

// NewBARK returns a fresh BARK instance composed of either the uniARCAD or
// lite-uniARCAD sub-protocols.
func NewLiteBARK(uni lite) *liteBARK {
	return &liteBARK{uni: uni}
}

// Init initialized the BARK protocols and returns two user states.
func (b liteBARK) Init() (alice, bob *User, err error) {
	sa, ra, err := b.uni.Init()
	if err != nil {
		return nil, nil, err
	}

	sb, rb, err := b.uni.Init()
	if err != nil {
		return nil, nil, err
	}

	hk := make([]byte, hashKeySize)
	if _, err := rand.Read(hk); err != nil {
		return nil, nil, err
	}

	alice = &User{
		Hk:     hk,
		Sender: [][]byte{sa}, Receiver: [][]byte{rb},
		Hsent: []byte{}, Hreceived: []byte{},
	}
	bob = &User{
		Hk:     hk,
		Sender: [][]byte{sb}, Receiver: [][]byte{ra},
		Hsent: []byte{}, Hreceived: []byte{},
	}
	return
}

// Send invokes the BARK send routine. It returns a session key
// and ciphertext to be sent across the channel.
func (b liteBARK) Send(user *User) (k, ct []byte, err error) {
	s, r, err := b.uni.Init()
	if err != nil {
		return nil, nil, err
	}
	user.Receiver = append(user.Receiver, r)

	k = make([]byte, sessionKeySize)
	if _, err := rand.Read(k); err != nil {
		return nil, nil, err
	}

	onion, err := primitives.Encode(&barkBlock{State: s, Key: k})
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to encode bark message")
	}

	i := 0
	for j, s := range user.Sender {
		if s != nil {
			i = j
			break
		}
	}

	u := len(user.Sender) - 1
	for j := u; j >= i; j-- {
		index := []byte(strconv.Itoa(u - j))
		sj, o, err := b.uni.Send(user.Sender[j], append(index, user.Hsent...), onion, j == u)
		if err != nil {
			return nil, nil, err
		}
		user.Sender[j], onion = sj, o

		if j < u {
			user.Sender[j] = nil
		}
	}

	ct, err = primitives.Encode(barkCiphertext{
		I:  []byte(strconv.Itoa(u - i)),
		Hs: user.Hsent, Onion: onion,
	})
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to encode bark ciphertext")
	}
	user.Hsent = primitives.Digest(hmac.New(sha256.New, user.Hk), ct)
	return
}

// Receive invokes the BARK receive routine for a given ciphertext and
// returns the established session key.
func (b liteBARK) Receive(user *User, ct []byte) (k []byte, err error) {
	var c barkCiphertext
	if err := primitives.Decode(ct, &c); err != nil {
		return nil, errors.Wrap(err, "unable to decode bark ciphertext")
	}
	if !bytes.Equal(c.Hs, user.Hreceived) {
		return nil, errors.New("Hsent != Hreceived")
	}

	i := 0
	for j, s := range user.Receiver {
		if s != nil {
			i = j
			break
		}
	}

	n, _ := strconv.Atoi(string(c.I))
	if i+n >= len(user.Receiver) {
		return nil, errors.New("participants are out of sync")
	}

	onion := c.Onion

	var upds []byte
	for j := i; j <= i+n; j++ {
		index := []byte(strconv.Itoa(i + n - j))
		upd, o, err := b.uni.Receive(user.Receiver[j], append(index, user.Hreceived...), onion)
		if err != nil {
			return nil, err
		}
		onion = o
		upds = upd
	}

	var block barkBlock
	if err := primitives.Decode(onion, &block); err != nil {
		return nil, err
	}
	k = block.Key

	user.Sender = append(user.Sender, block.State)

	for j := i; j <= i+n-1; j++ {
		user.Receiver[j] = nil
	}
	user.Receiver[i+n] = upds
	user.Hreceived = primitives.Digest(hmac.New(sha256.New, user.Hk), ct)

	return
}
