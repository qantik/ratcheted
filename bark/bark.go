// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package bark

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strconv"
)

const (
	hashKeySize    = 16
	sessionKeySize = 16
)

type uni interface {
	Init() ([]byte, []byte, error)
	Send(state, ad, pt []byte) ([]byte, []byte, error)
	Receive(state, ad, ct []byte) ([]byte, []byte, error)
}

type BARK struct {
	//uniARK *UNIARK
	uni uni
}

// barkBlock bundles BARK plaintext material.
type barkBlock struct {
	State, Key []byte
}

type participant struct {
	Hk               []byte   // hashing key
	Sender, Receiver [][]byte // states
	Hsent            []byte   // iterated hash of sent messages
	Hreceived        []byte   // iterated hash received messages
}

func NewBARK(uni uni) *BARK {
	return &BARK{uni: uni}
}

func (b BARK) Init() ([]byte, []byte, error) {
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

	pa := participant{
		Hk:     hk,
		Sender: [][]byte{sa}, Receiver: [][]byte{rb},
		Hsent: []byte{}, Hreceived: []byte{},
	}
	p1, err := json.Marshal(&pa)
	if err != nil {
		return nil, nil, err
	}

	pb := participant{
		Hk:     hk,
		Sender: [][]byte{sb}, Receiver: [][]byte{ra},
		Hsent: []byte{}, Hreceived: []byte{},
	}
	p2, err := json.Marshal(&pb)
	if err != nil {
		return nil, nil, err
	}

	return p1, p2, nil
}

func (b BARK) Send(state []byte) (upd, k []byte, ct [][]byte, err error) {
	var p participant
	if err = json.Unmarshal(state, &p); err != nil {
		return
	}

	s, r, err := b.uni.Init()
	if err != nil {
		return nil, nil, nil, err
	}

	p.Receiver = append(p.Receiver, r)

	k = make([]byte, sessionKeySize)
	if _, err := rand.Read(k); err != nil {
		return nil, nil, nil, err
	}

	//fmt.Println("ka:", k)

	//onion := append(k, s...)
	//onion := merge(s, k)
	onion, err := json.Marshal(&barkBlock{State: s, Key: k})
	if err != nil {
		return nil, nil, nil, err
	}

	i := 0
	for j, s := range p.Sender {
		if s != nil {
			i = j
			break
		}
	}

	u := len(p.Sender) - 1
	for j := u; j >= i; j-- {
		//fmt.Println(i, j, u)
		index := []byte(strconv.Itoa(u - j))
		//fmt.Println("a:", string(p.Sender[j]), index, p.Hsent, string(onion))
		//fmt.Println("ao:", onion)
		sj, o, err := b.uni.Send(p.Sender[j], append(index, p.Hsent...), onion)
		if err != nil {
			return nil, nil, nil, err
		}
		p.Sender[j], onion = sj, o

		if j < u {
			p.Sender[j] = nil
		}
	}

	ct = [][]byte{[]byte(strconv.Itoa(u - i)), p.Hsent, onion}

	mac := hmac.New(sha256.New, p.Hk)
	mac.Write(bytes.Join(ct, nil))
	p.Hsent = mac.Sum(nil)

	upd, err = json.Marshal(&p)
	return
}

func (b BARK) Receive(state []byte, ct [][]byte) (upd, k []byte, err error) {
	var p participant
	if err = json.Unmarshal(state, &p); err != nil {
		return
	}
	if !bytes.Equal(ct[1], p.Hreceived) {
		return nil, nil, errors.New("Hsent != Hreceived")
	}

	i := 0
	for j, s := range p.Receiver {
		if s != nil {
			i = j
			break
		}
	}

	n, _ := strconv.Atoi(string(ct[0]))
	//fmt.Println("-------------------", n, i, len(p.Receiver))
	if i+n >= len(p.Receiver) {
		return nil, nil, errors.New("participants are out of sync")
	}

	onion := ct[2]

	upds := make([][]byte, i)
	for j := i; j <= i+n; j++ {
		//fmt.Println(i, j, n, len(p.Sender))
		index := []byte(strconv.Itoa(i + n - j))
		//fmt.Println("b:", string(p.Receiver[j]), index, p.Hreceived, string(onion))
		upd, o, err := b.uni.Receive(p.Receiver[j], append(index, p.Hreceived...), onion)
		//fmt.Println("kb:", o)
		if err != nil {
			return nil, nil, err
		}
		onion = o
		upds = append(upds, upd)
	}

	//p.Sender = append(p.Sender, onion[sessionKeySize:])
	//k = onion[:sessionKeySize]
	//fmt.Println("b:", onion)
	var block barkBlock
	if err := json.Unmarshal(onion, &block); err != nil {
		return nil, nil, err
	}

	//l := split(onion)
	//p.Sender = append(p.Sender, l[0])
	p.Sender = append(p.Sender, block.State)
	k = block.Key
	//k = l[1]

	for j := i; j <= i+n-1; j++ {
		p.Receiver[j] = nil
	}
	//fmt.Println("TTTTTTTTTTTTT", i, n, len(upds), len(p.Receiver))
	p.Receiver[i+n] = upds[i+n]

	mac := hmac.New(sha256.New, p.Hk)
	mac.Write(bytes.Join(ct, nil))
	p.Hreceived = mac.Sum(nil)

	upd, err = json.Marshal(&p)
	return
}
