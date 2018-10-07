// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package r2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

type LiteUniARCAD struct{}

func NewLiteUniARCAD() *LiteUniARCAD {
	return &LiteUniARCAD{}
}

func (l LiteUniARCAD) Init() (s, r []byte, err error) {
	s = make([]byte, 16)
	if _, err := rand.Read(s); err != nil {
		return nil, nil, err
	}

	r = make([]byte, 16)
	copy(r, s)

	return
}

func (l LiteUniARCAD) Send(state, ad, pt []byte) (upd, ct []byte, err error) {
	block, err := aes.NewCipher(state)
	if err != nil {
		return nil, nil, err
	}

	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	upd = make([]byte, 16)
	if _, err := rand.Read(upd); err != nil {
		return nil, nil, err
	}

	text := append(upd, append(sep, pt...)...)

	ct = gcm.Seal(nil, nonce[:], text, ad)
	ct = append(nonce[:], append(sep, ct...)...)
	//fmt.Println("out:", ct)
	//fmt.Println("out nonce:", nonce)
	return
}

func (l LiteUniARCAD) Receive(state, ad, ct []byte) (upd, pt []byte, err error) {
	//fmt.Println("in:", ct)
	//parts := bytes.Split(ct, sep)
	parts := split(ct)

	nonce := parts[0]
	//fmt.Println("in nonce:", nonce)
	ct = parts[1]

	block, err := aes.NewCipher(state)
	if err != nil {
		return nil, nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	text, err := gcm.Open(nil, nonce, ct, ad)
	if err != nil {
		return nil, nil, err
	}

	//parts = bytes.Split(text, sep)
	parts = split(text)

	upd = parts[0]
	pt = parts[1]

	return

}
