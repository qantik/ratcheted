package r2

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

type BARK struct {
	uniARK *UNIARK
}

type participant struct {
	Hk               []byte   // hashing key
	Sender, Receiver [][]byte // states
	Hsent            []byte   // iterated hash of sent messages
	Hreceived        []byte   // iterated hash received messages
}

func NewBARK(uniARK *UNIARK) *BARK {
	return &BARK{uniARK: uniARK}
}

func (b BARK) Init() ([]byte, []byte, error) {
	sa, ra, err := b.uniARK.Init()
	if err != nil {
		return nil, nil, err
	}

	sb, rb, err := b.uniARK.Init()
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

	s, r, err := b.uniARK.Init()
	if err != nil {
		return nil, nil, nil, err
	}

	p.Receiver = append(p.Receiver, r)

	k = make([]byte, sessionKeySize)
	if _, err := rand.Read(k); err != nil {
		return nil, nil, nil, err
	}

	//fmt.Println("ka:", k)

	onion := append(k, s...)

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
		sj, o, err := b.uniARK.Send(p.Sender[j], append(index, p.Hsent...), onion)
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
		upd, o, err := b.uniARK.Receive(p.Receiver[j], append(index, p.Hreceived...), onion)
		if err != nil {
			return nil, nil, err
		}
		onion = o
		upds = append(upds, upd)
	}

	p.Sender = append(p.Sender, onion[sessionKeySize:])
	k = onion[:sessionKeySize]
	//fmt.Println("kb:", k)

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
