// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package r1

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
)

type urkeSender struct {
	pk *rsa.PublicKey

	K  []byte // chaining key
	km []byte // MAC key
	t  []byte // transcript accumulator
}

type urkeReceiver struct {
	sk *rsa.PrivateKey

	K  []byte // chaining key
	km []byte // MAC key
	t  []byte // transcript accumulator
}

func urkeInit() (*urkeSender, *urkeReceiver) {
	sk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err) // FIXME: Proper error handling
	}

	K := make([]byte, 16)
	rand.Read(K)

	km := make([]byte, 16)
	rand.Read(km)

	snd := &urkeSender{pk: &sk.PublicKey, K: K, km: km, t: []byte{}}
	rcv := &urkeReceiver{sk: sk, K: K, km: km, t: []byte{}}

	return snd, rcv
}

func (u *urkeSender) encapsulate() (k, c []byte) {
	r := make([]byte, 16)
	rand.Read(r)

	c, _ = rsa.EncryptPKCS1v15(rand.Reader, u.pk, r)
	k = digest(sha256.New(), r)

	return
}

func (u *urkeSender) send(ad []byte) (ko, C []byte) {
	k, c := u.encapsulate()

	tau := digest(hmac.New(sha256.New, u.km), ad, c)

	C = append(c, tau...)
	u.t = append(u.t, append(ad, C...)...)

	sum := digest(sha512.New384(), u.K, k, u.t)
	ko, u.K, u.km = sum[0:16], sum[16:32], sum[32:48]

	return
}

func (u *urkeReceiver) extract(c []byte) (k []byte) {
	r, _ := rsa.DecryptPKCS1v15(rand.Reader, u.sk, c)
	k = digest(sha256.New(), r)

	return
}

func (u *urkeReceiver) receive(ad, C []byte) (ko []byte) {
	c, tau := C[0:256], C[256:288]

	if bytes.Compare(tau, digest(hmac.New(sha256.New, u.km), ad, c)) != 0 {
		panic("failed to verify MAC")
	}

	k := u.extract(c)

	u.t = append(u.t, append(ad, C...)...)

	sum := digest(sha512.New384(), u.K, k, u.t)
	ko, u.K, u.km = sum[0:16], sum[16:32], sum[32:48]

	return
}
