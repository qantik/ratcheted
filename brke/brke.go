// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package brke

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"strconv"

	"github.com/pkg/errors"

	"github.com/qantik/ratcheted/primitives"
	"github.com/qantik/ratcheted/primitives/hibe"
	"github.com/qantik/ratcheted/primitives/signature"
)

const (
	seedSize        = 16
	chainingKeySize = 16
	sessionKeySize  = 16
)

var (
	/*
	   REMOVE ERROR MESSAGES. They're unnecessary, simply use inline errors.
	*/
	errInvalidSignature = "unable to verify signature"
	errOutOfSync        = "communicating parties are out-of-sync"
	errPRNG             = "error while polling random number generator"
	errKUKEM            = "error while polling ku-kuKEM"
)

// BRKE designates the PT18 protocol object defined by a ku-KEM scheme and a
// one-time signature algorithm.
type BRKE struct {
	kuKEM     *kuKEM
	signature signature.Signature
}

// User designates a participant in the protocol that can both send and receive
// messages. It has to be passed as an argument to both the send and receive routines.
type User struct {
	// A user state is comprised of two sub-states (r,s) that are continuously updated upon
	// sending or receving messages. The r and s sub-states are derived from the SRKE
	// receiver and sender states but due to the interleaving of the SRKE parts in the
	// BRKE algorithm both states are needed to send and receive messages.
	r *r
	s *s

	// User identifier string.
	name string
}

// r comprises the first sub-state of a user.
type r struct {
	SK map[int][]byte // SK are the established ku-KEM secret keys for different epochs.

	E0 int // E0 is the oldest active epoch.
	E1 int // E1 is the newest active epoch.
	r  int // r is the number of received messages.

	L map[int][]byte // L stores the created ciphertexts for different epochs.

	sgk []byte // sgk is the signature scheme signing key.
	K   []byte // K is one of the two created chaining keys.

	// t is the accumulated transcript of the current communication.
	// FIXME: It may be better to use a 2-dim array instead of glueing together slices.
	t []byte
}

// s comprises the second sub-state of a user.
type s struct {
	PK map[int][]byte // PK are the established ku-KEM public keys for different epochs.

	E0 int // EO is the oldest active epoch.
	E1 int // E1 is the newest active epoch.
	s  int // s is the number of sent messages.

	L map[int][]byte // L stores the created ciphertexts for different epochs.

	vfk []byte // vfk is the signature scheme verifying key.
	K   []byte // K is one of the two crated chaining keys.

	// t is the accumulated transcript of the current communication.
	// FIXME: It may be better to use a 2-dim array instead of glueing together slices.
	t []byte
}

// NewBRKE creates a fresh BRKE protocol instance.
//
// TODO: Make RNG a parameter.
func NewBRKE(hibe hibe.HIBE, signature signature.Signature) *BRKE {
	return &BRKE{kuKEM: &kuKEM{hibe: hibe}, signature: signature}
}

// Init creates two fresh users objects that can communicate with each other.
//
// TODO: Decide on what to do with the names.
func (b BRKE) Init() (*User, *User, error) {
	// Generate two sets of signature key pairs.
	vfka, sgka, err := b.signature.Generate()
	if err != nil {
		return nil, nil, errors.Wrap(err, errPRNG)
	}
	vfkb, sgkb, err := b.signature.Generate()
	if err != nil {
		return nil, nil, errors.Wrap(err, errPRNG)
	}

	// Generate two sets of key-updatable KEM key pairs.
	var seed [seedSize]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, nil, errors.Wrap(err, errPRNG)
	}
	pka, ska, err := b.kuKEM.generate(seed[:])
	if err != nil {
		return nil, nil, errors.Wrap(err, errKUKEM)
	}
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, nil, errors.Wrap(err, errPRNG)
	}
	pkb, skb, err := b.kuKEM.generate(seed[:])
	if err != nil {
		return nil, nil, errors.Wrap(err, errKUKEM)
	}

	// Generate two chaining keys. Both users receive both of them.
	var Ka [chainingKeySize]byte
	var Kb [chainingKeySize]byte
	if _, err := rand.Read(Ka[:]); err != nil {
		return nil, nil, errors.Wrap(err, errPRNG)
	}
	if _, err := rand.Read(Kb[:]); err != nil {
		return nil, nil, errors.Wrap(err, errPRNG)
	}

	// Create sub-states for user a.
	sa := &s{
		PK: map[int][]byte{0: pkb},
		E0: 0, E1: 0, s: 0,
		L:   map[int][]byte{0: []byte{}},
		vfk: vfkb, K: Kb[:],
		t: []byte{},
	}
	ra := &r{
		SK: map[int][]byte{0: ska},
		E0: 0, E1: 0, r: 0,
		L:   map[int][]byte{},
		sgk: sgka, K: Ka[:],
		t: []byte{},
	}
	ua := &User{r: ra, s: sa, name: "alice"}

	// Create sub-states for user b.
	sb := &s{
		PK: map[int][]byte{0: pka},
		E0: 0, E1: 0, s: 0,
		L:   map[int][]byte{0: []byte{}},
		vfk: vfka, K: Ka[:],
		t: []byte{},
	}
	rb := &r{
		SK: map[int][]byte{0: skb},
		E0: 0, E1: 0, r: 0,
		L:   map[int][]byte{},
		sgk: sgkb, K: Kb[:],
		t: []byte{},
	}
	ub := &User{r: rb, s: sb, name: "bob"}

	return ua, ub, nil
}

// oracle implements the random oracle specified in the paper by spliting a SHA512 digest.
func oracle(Ks, ks, ts []byte) ([]byte, []byte, []byte) {
	sum := primitives.Digest(sha512.New(), Ks, ks, ts)

	// TODO: Make this more elegant.
	ko := sum[:sessionKeySize]
	Ks = sum[sessionKeySize : sessionKeySize+chainingKeySize]
	coins := sum[sessionKeySize+chainingKeySize : sessionKeySize+chainingKeySize+seedSize]
	return ko, Ks, coins
}

// Send creates a new session key and a corresponding ciphertext that has to be passed
// to the other user in order to notify him of the update.
func (b BRKE) Send(user *User, ad []byte) ([]byte, [][]byte, error) {
	// Generate new signature and ku-KEM key pairs. Store the signing key and append
	// the two public keys to the ciphertext.
	vfks, sgks, err := b.signature.Generate()
	if err != nil {
		return nil, nil, errors.Wrap(err, errPRNG)
	}
	var seed [seedSize]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, nil, errors.Wrap(err, errPRNG)
	}
	pks, sks, err := b.kuKEM.generate(seed[:])
	if err != nil {
		return nil, nil, errors.Wrap(err, errKUKEM)
	}
	user.r.E1 += 1
	user.r.SK[user.r.E1] = sks
	C := [][]byte{[]byte(strconv.Itoa(user.r.r)), pks, vfks, []byte(strconv.Itoa(user.s.E1))}

	// Encapsulate new intermediate hashing keys for each active s-epoch. Append
	// the generated ciphers to the above ciphertext.
	ks := []byte{}
	for i := user.s.E0; i <= user.s.E1; i++ {
		c1, c2, err := b.kuKEM.encrypt(user.s.PK[i])
		if err != nil {
			return nil, nil, errors.Wrap(err, errKUKEM)
		}
		ks, C = append(ks, c1...), append(C, c2)
	}

	// Sign ciphertext and append it to the history.
	sig, err := b.signature.Sign(user.r.sgk, append(ad, bytes.Join(C, nil)...))
	if err != nil {
		return nil, nil, errors.Wrap(err, errPRNG)
	}
	C = append(C, sig)
	user.r.L[user.r.E1] = append(ad, bytes.Join(C, nil)...)
	user.r.sgk = sgks

	// Poll oracle to establish the session key, chaining key and a new ku-KEM public key
	// for the latest epoch. This erases all previously created ku-KEM public keys since
	// there can only be a single active s-epoch after a sending operation.
	user.s.t = append(user.s.t, append(ad, bytes.Join(C, nil)...)...)
	ko, Ks, coins := oracle(user.s.K, ks, user.s.t)
	pk, _, err := b.kuKEM.generate(coins)
	if err != nil {
		return nil, nil, errors.Wrap(err, errKUKEM)
	}
	for i := 0; i < user.s.E1; i++ {
		user.s.PK[i] = nil
	}
	user.s.PK[user.s.E1] = pk
	user.s.E0 = user.s.E1
	user.s.s += 1
	user.s.K = Ks
	user.s.L[user.s.s] = append(ad, bytes.Join(C, nil)...)

	return ko, C, nil
}

// Receive receives a newly established session key created by the opposing user.
func (b BRKE) Receive(user *User, ad []byte, C [][]byte) ([]byte, error) {
	// Update s-transcript.
	ts := append(ad, bytes.Join(C, nil)...)
	user.s.t = append(user.s.t, ts...)

	sig := C[len(C)-1]
	C = C[:len(C)-1]
	if err := b.signature.Verify(user.s.vfk, append(ad, bytes.Join(C, nil)...), sig); err != nil {
		return nil, errors.Wrap(err, errInvalidSignature)
	}

	// Unwind ciphertext and delete old ciphertext for out-dated r-epochs.
	r, pks, vfk := C[0], C[1], C[2]
	C = C[3:]
	rr, err := strconv.Atoi(string(r))
	if err != nil || user.s.L[rr] == nil {
		return nil, errors.New(errOutOfSync)
	}
	for i := 0; i < rr; i++ {
		user.s.L[i] = nil
	}
	user.s.L[rr] = []byte{}

	for i := rr + 1; i <= user.s.s; i++ {
		pks, err = b.kuKEM.updatePublicKey(pks, user.s.L[i])
		if err != nil {
			panic(err)
		}
	}
	user.s.E1 += 1
	user.s.PK[user.s.E1] = pks
	user.s.vfk = vfk

	// Check that received epoch is still active and delete old ciphertexts.
	e, _ := strconv.Atoi(string(C[0]))
	C = C[1:]
	if e < user.r.E0 || e > user.r.E1 {
		return nil, errors.New(errOutOfSync)
	}
	for i := user.r.E0 + 1; i <= e; i++ {
		user.r.t = append(user.r.t, user.r.L[i]...)
	}
	for i := 0; i <= e; i++ {
		user.r.L[i] = nil
	}

	// Recreate hashing key and poll oracle to establish the same session key, chaining key
	// and ku-KEM secret key as the initiating party.
	ks := []byte{}
	for i := user.r.E0; i <= e; i++ {
		c := C[0]
		C = C[1:]
		k, err := b.kuKEM.decrypt(user.r.SK[i], c)
		if err != nil {
			return nil, errors.Wrap(err, errKUKEM)
		}
		ks = append(ks, k...)
	}
	user.r.t = append(user.r.t, ts...)
	ko, Kr, coins := oracle(user.r.K, ks, user.r.t)
	_, sk, err := b.kuKEM.generate(coins)
	if err != nil {
		return nil, errors.Wrap(err, errKUKEM)
	}

	// Delete old ku-KEM secret keys and update those which are still active.
	for i := 0; i <= e-1; i++ {
		user.r.SK[i] = nil
	}
	user.r.SK[e] = sk
	for i := e + 1; i <= user.r.E1; i++ {
		s, err := b.kuKEM.updateSecretKey(user.r.SK[i], ts)
		if err != nil {
			return nil, errors.Wrap(err, errKUKEM)
		}
		user.r.SK[i] = s
	}
	user.r.E0 = e
	user.r.r += 1
	user.r.K = Kr

	return ko, nil
}
