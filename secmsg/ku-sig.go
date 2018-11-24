// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package secmsg

import (
	"strconv"

	"github.com/pkg/errors"

	"github.com/qantik/ratcheted/primitives"
	"github.com/qantik/ratcheted/primitives/signature"
)

// kuSig implements a key-updatable digital signature scheme based on a
// one-time signature scheme.
type kuSig struct {
	signature signature.Signature
}

// kuSigPublicKey bundles the public key material.
type kuSigPublicKey struct {
	PK []byte // PK is the ku-Sig public key.
	R  int    // R is a counter of verified messages.
}

// kuSigPrivateKey bundles the private key material.
type kuSigPrivateKey struct {
	SK []byte // SK is the ku-Sig private key.
	S  int    // S is a counter of signed messages.
}

// kuSigBundle groups the signature and updated ku-Sig public key.
type kuSigBundle struct {
	Sig []byte // Sig is the signature of a message.
	PK  []byte // VK is the updated ku-Sig public key.
}

// generate creates fresh ku-Sig public/private key pair.
func (k kuSig) generate() (pk, sk []byte, err error) {
	fpk, fsk, err := k.signature.Generate()
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to generate ots key pair")
	}

	pk, err = primitives.Encode(&kuSigPublicKey{PK: fpk, R: 0})
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to encode ku-sig public key")
	}
	sk, err = primitives.Encode(&kuSigPrivateKey{SK: fsk, S: 0})
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to encode ku-sig private key")
	}
	return
}

// sign creates a ku-sig bundle containing the OTS signature of the message and a fresh
// OTS public key. It returns this bundle and the corresponding updated ku-Sig private key.
func (k kuSig) sign(sk, msg []byte) (upd, bundle []byte, err error) {
	var private kuSigPrivateKey
	if err := primitives.Decode(sk, &private); err != nil {
		return nil, nil, errors.Wrap(err, "unable to decode ku-sig private key")
	}

	fpk, fsk, err := k.signature.Generate()
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to generate ots key pair")
	}

	data := append(fpk, append([]byte(strconv.Itoa(private.S+1)), msg...)...)
	sig, err := k.signature.Sign(private.SK, data)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to sign message")
	}

	private.SK = fsk
	private.S++

	bundle, err = primitives.Encode(&kuSigBundle{Sig: sig, PK: fpk})
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to encode ku-sig bundle")
	}
	upd, err = primitives.Encode(&private)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to encode updated ku-sig private key")
	}
	return
}

// verify checks the signature of msg and updates the ku-sig public key.
func (k kuSig) verify(pk, msg, bdl []byte) ([]byte, error) {
	var public kuSigPublicKey
	if err := primitives.Decode(pk, &public); err != nil {
		return nil, errors.Wrap(err, "unable to decode ku-sig public key")
	}
	var bundle kuSigBundle
	if err := primitives.Decode(bdl, &bundle); err != nil {
		return nil, errors.Wrap(err, "unable to decode ku-sig bundle")
	}

	data := append(bundle.PK, append([]byte(strconv.Itoa(public.R+1)), msg...)...)
	if err := k.signature.Verify(public.PK, data, bundle.Sig); err != nil {
		return nil, errors.Wrap(err, "unable to verify ots signature")
	}

	public.PK = bundle.PK
	public.R++

	upd, err := primitives.Encode(&public)
	if err != nil {
		return nil, errors.Wrap(err, "unable to encode updated ku-sig public key")
	}
	return upd, nil
}
