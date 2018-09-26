package r2

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"math/big"

	"golang.org/x/crypto/hkdf"
)

type ECIES struct {
	curve elliptic.Curve
}

type privateKey struct{ K *big.Int }
type publicKey struct{ Kx, Ky *big.Int }

type Cipher struct {
	Rx, Ry *big.Int
	C, D   []byte
}

func NewECIES(curve elliptic.Curve) *ECIES {
	return &ECIES{curve: curve}
}

func (e ECIES) GenerateKeys() (sk, pk []byte, err error) {
	k, err := randFieldElement(e.curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	Kx, Ky := e.curve.ScalarBaseMult(k.Bytes())

	private := &privateKey{K: k}
	sk, err = json.Marshal(private)
	if err != nil {
		return
	}
	public := &publicKey{Kx: Kx, Ky: Ky}
	pk, err = json.Marshal(public)
	if err != nil {
		return
	}

	return
}

func (e ECIES) Encrypt(pk, msg []byte) ([]byte, error) {
	var public publicKey
	if err := json.Unmarshal(pk, &public); err != nil {
		return nil, err
	}

	r, err := randFieldElement(e.curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	Rx, Ry := e.curve.ScalarBaseMult(r.Bytes())
	Px, _ := e.curve.ScalarMult(public.Kx, public.Ky, r.Bytes())

	hkdf := hkdf.New(sha256.New, Px.Bytes(), nil, nil)

	ke := make([]byte, 16)
	n, err := io.ReadFull(hkdf, ke)
	if n != len(ke) || err != nil {
		return nil, err
	}
	km := make([]byte, 16)
	n, err = io.ReadFull(hkdf, km)
	if n != len(km) || err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(ke)
	if err != nil {
		return nil, err
	}

	padded := pad(msg)

	c := make([]byte, aes.BlockSize+len(padded))
	iv := c[:aes.BlockSize]
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(c[aes.BlockSize:], padded)

	mac := hmac.New(sha256.New, km)
	mac.Write(c)
	d := mac.Sum(nil)

	ct := Cipher{Rx: Rx, Ry: Ry, C: c, D: d}
	enc, err := json.Marshal(&ct)
	if err != nil {
		return nil, err
	}
	return enc, nil
}

func (e *ECIES) Decrypt(sk, ct []byte) ([]byte, error) {
	var private privateKey
	if err := json.Unmarshal(sk, &private); err != nil {
		return nil, err
	}

	var c Cipher
	if err := json.Unmarshal(ct, &c); err != nil {
		return nil, err
	}

	Px, _ := e.curve.ScalarMult(c.Rx, c.Ry, private.K.Bytes())

	hkdf := hkdf.New(sha256.New, Px.Bytes(), nil, nil)

	ke := make([]byte, 16)
	n, err := io.ReadFull(hkdf, ke)
	if n != len(ke) || err != nil {
		return nil, err
	}
	km := make([]byte, 16)
	n, err = io.ReadFull(hkdf, km)
	if n != len(km) || err != nil {
		return nil, err
	}

	mac := hmac.New(sha256.New, km)
	mac.Write(c.C)
	tau := mac.Sum(nil)
	if !bytes.Equal(tau, c.D) {
		return nil, errors.New("failed to verify mac")
	}

	block, err := aes.NewCipher(ke)
	if err != nil {
		return nil, err
	}

	iv := c.C[:aes.BlockSize]
	c.C = c.C[aes.BlockSize:]

	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(c.C, c.C)

	unpadded, err := unpad(c.C)
	if err != nil {
		return nil, err
	}

	return unpadded, nil
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
		return nil, errors.New("unpad error")
	}

	return src[:(length - unpadding)], nil
}
