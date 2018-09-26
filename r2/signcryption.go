package r2

import (
	"crypto/elliptic"
	"io"
	"math/big"
)

var one = new(big.Int).SetInt64(1)

const maxMessageLength = 1024

func randFieldElement(c elliptic.Curve, rand io.Reader) (k *big.Int, err error) {
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)

	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}

	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)

	return

}

// GenerateKey generates a public and private key pair.
//func GenerateKey(c elliptic.Curve, rand io.Reader) (*PrivateKey, error) {
//	k, err := randFieldElement(c, rand)
//	if err != nil {
//		return nil, err
//	}
//
//	priv := new(PrivateKey)
//	priv.PublicKey.Curve = c
//	priv.D = k
//	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
//
//	return priv, nil
//
//}

type Signcryption struct {
	ecies *ECIES
	ecdsa *ECDSA
}

func NewSigncryption(ecies *ECIES, ecdsa *ECDSA) *Signcryption {
	return &Signcryption{ecies: ecies, ecdsa: ecdsa}
}

func (s *Signcryption) GenerateSignKeys() (sk, pk []byte, err error) {
	sk, pk, err = s.ecdsa.GenerateKeys()
	return
}

func (s *Signcryption) GenerateCipherKeys() (sk, pk []byte, err error) {
	sk, pk, err = s.ecies.GenerateKeys()
	return
}

func (s *Signcryption) Signcrypt(sks, pkr, ad, msg []byte) ([]byte, error) {
	sig, err := s.ecdsa.Sign(sks, append(ad, msg...))
	if err != nil {
		return nil, err
	}

	ct, err := s.ecies.Encrypt(pkr, append(sig, msg...))
	if err != nil {
		return nil, err
	}

	return ct, nil
}

func (s *Signcryption) Unsigncrypt(skr, pks, ad, ct []byte) ([]byte, error) {
	dec, err := s.ecies.Decrypt(pks, ct)
	if err != nil {
		return nil, err
	}

	l := s.ecdsa.SignatureLength()
	sig, msg := dec[:l], dec[l:]

	//rr := new(big.Int).SetBytes(signature[:s.curve.Params().BitSize/8])
	//ss := new(big.Int).SetBytes(signature[s.curve.Params().BitSize/8:])

	if err := s.ecdsa.Verify(skr, append(ad, msg...), sig); err != nil {
		return nil, err
	}

	return msg, nil
}
