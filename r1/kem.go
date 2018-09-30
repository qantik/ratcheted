package r1

import "encoding/json"

type hhibe interface {
	Setup(seed []byte) ([]byte, []byte, error)
	Extract(ancestor []byte, id [][]byte) ([]byte, error)
	Encrypt(params, message []byte, id [][]byte) ([]byte, []byte, error)
	Decrypt(entity, c1, c2 []byte) ([]byte, error)
}

type kem struct {
	hibe hhibe
}

type kemPublicKey struct {
	PK []byte   // PK designates the HIBE parameters.
	A  [][]byte // A is associated data used as the identity in the HIBE scheme.
}

func (k kem) Generate(seed []byte) (pk, sk []byte, err error) {
	params, root, err := k.hibe.Setup(seed)
	if err != nil {
		return nil, nil, err
	}

	sk, err = k.hibe.Extract(root, [][]byte{[]byte{}})
	if err != nil {
		return
	}

	pk, err = json.Marshal(&kemPublicKey{PK: params, A: [][]byte{[]byte{}}})
	return
}

func (k kem) UpdatePublicKey(pk, ad []byte) ([]byte, error) {
	var p kemPublicKey
	if err := json.Unmarshal(pk, &p); err != nil {
		return nil, err
	}

	p.A = append(p.A, ad)
	return json.Marshal(&p)
}

func (k kem) UpdateSecretKey(sk []byte, ad [][]byte) ([]byte, error) {
	return k.hibe.Extract(sk, ad)
}

func (k kem) Encrypt(pk []byte) ([]byte, []byte, error) {
	var p kemPublicKey
	if err := json.Unmarshal(pk, &p); err != nil {
		return nil, nil, err
	}

	return k.hibe.Encrypt(p.PK, nil, p.A)
}

func (k kem) Decrypt(sk, ct []byte) ([]byte, error) {
	return k.hibe.Decrypt(sk, nil, ct)
}
