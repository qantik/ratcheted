package r2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"math/big"
)

type ECDSA struct {
	curve elliptic.Curve
}

type ecdsaPrivate struct{ *ecdsa.PrivateKey }
type ecdsaPublic struct{ *ecdsa.PublicKey }

func NewECDSA(curve elliptic.Curve) *ECDSA {
	return &ECDSA{curve: curve}
}

// SignatureLength returns the size of a ECDSA signature in bytes.
func (e ECDSA) SignatureLength() int {
	return 2 * e.curve.Params().BitSize / 8
}

func (e ECDSA) GenerateKeys() (private, public []byte, err error) {
	sk, err := ecdsa.GenerateKey(e.curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	private, err = json.Marshal(&ecdsaPrivate{sk})
	if err != nil {
		return nil, nil, err
	}
	public, err = json.Marshal(&ecdsaPublic{&sk.PublicKey})
	if err != nil {
		return nil, nil, err
	}

	return
}

func (e ECDSA) Sign(private, msg []byte) ([]byte, error) {
	var sk ecdsaPrivate
	if err := json.Unmarshal(private, &sk); err != nil {
		return nil, err
	}

	sha := sha256.New()
	sha.Write(msg)
	digest := sha.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, sk.PrivateKey, digest)
	if err != nil {
		return nil, err
	}

	sig := append(r.Bytes(), s.Bytes()...)

	// FIXME: Every once in a while a signature with bogus length is created that
	// is impossible to verify in that case a new one is created.
	if len(sig) != e.SignatureLength() {
		return e.Sign(private, msg)
	}
	return append(r.Bytes(), s.Bytes()...), nil
}

func (e ECDSA) Verify(public, msg, sig []byte) error {
	var pk ecdsaPublic
	if err := json.Unmarshal(public, &pk); err != nil {
		return err
	}

	sha := sha256.New()
	sha.Write(msg)
	digest := sha.Sum(nil)

	r := new(big.Int).SetBytes(sig[:e.curve.Params().BitSize/8])
	s := new(big.Int).SetBytes(sig[e.curve.Params().BitSize/8:])

	if !ecdsa.Verify(pk.PublicKey, digest, r, s) {
		return errors.New("unable to verify signature")
	}

	return nil
}

func (e ecdsaPrivate) MarshalJSON() ([]byte, error) {
	enc, err := x509.MarshalECPrivateKey(e.PrivateKey)
	if err != nil {
		return nil, err
	}

	return json.Marshal(struct{ PrivateKey []byte }{enc})
}

func (e *ecdsaPrivate) UnmarshalJSON(data []byte) error {
	var aux map[string][]byte
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	key, err := x509.ParseECPrivateKey(aux["PrivateKey"])
	if err != nil {
		return err
	}

	e.PrivateKey = key
	return nil
}

func (e ecdsaPublic) MarshalJSON() ([]byte, error) {
	enc, err := x509.MarshalPKIXPublicKey(e.PublicKey)
	if err != nil {
		return nil, err
	}

	return json.Marshal(struct{ PublicKey []byte }{enc})
}

func (e *ecdsaPublic) UnmarshalJSON(data []byte) error {
	var aux map[string][]byte
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	key, err := x509.ParsePKIXPublicKey(aux["PublicKey"])
	if err != nil {
		return err
	}

	e.PublicKey = key.(*ecdsa.PublicKey)
	return nil
}
