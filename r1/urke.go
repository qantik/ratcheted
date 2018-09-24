// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package r1

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
)

type URKE struct {
	kuKEM kuKEM
}

func NewURKE(kuKEM kuKEM) *URKE {
	return &URKE{kuKEM: kuKEM}
}

type urkeSender struct {
	pk []byte

	K  []byte
	km []byte
	t  []byte
}

type urkeReceiver struct {
	sk []byte

	K  []byte
	km []byte
	t  []byte
}

func (u *URKE) init() (*urkeSender, *urkeReceiver) {
	pk, sk := u.kuKEM.GenerateKeys()

	K := make([]byte, 16)
	rand.Read(K)

	km := make([]byte, 16)
	rand.Read(km)

	sender := &urkeSender{pk: pk, K: K, km: km, t: []byte{}}
	receiver := &urkeReceiver{sk: sk, K: K, km: km, t: []byte{}}

	return sender, receiver
}

func (u *URKE) send(sender *urkeSender, ad []byte) (ko, tau, cipher []byte) {
	k, c := u.kuKEM.Encrypt(sender.pk)
	cipher = c

	tau = digest(hmac.New(sha256.New, sender.km), ad, c)

	C := append(c, tau...)

	sender.t = append(sender.t, append(ad, C...)...)

	sum := digest(sha512.New(), sender.K, k, sender.t)
	ko, sender.K, sender.km = sum[0:16], sum[16:32], sum[32:48]

	sk := u.kuKEM.GenerateSecret(sum[48:64])
	sender.pk = u.kuKEM.GeneratePublicFromSecret(sk)

	return
}

func (u *URKE) receive(receiver *urkeReceiver, ad, tau, c []byte) (ko []byte) {
	if bytes.Compare(tau, digest(hmac.New(sha256.New, receiver.km), ad, c)) != 0 {
		panic("failed to verify MAC")
	}

	k := u.kuKEM.Decrypt(receiver.sk, c)

	C := append(c, tau...)
	receiver.t = append(receiver.t, append(ad, C...)...)

	sum := digest(sha512.New(), receiver.K, k, receiver.t)
	ko, receiver.K, receiver.km = sum[0:16], sum[16:32], sum[32:48]
	receiver.sk = u.kuKEM.GenerateSecret(sum[48:64])

	return
}
