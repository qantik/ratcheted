// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package dratch

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/qantik/ratcheted/primitives/encryption"
)

func TestFSA(t *testing.T) {
	require := require.New(t)

	fs := fsAEAD{aead: encryption.NewGCM(), pp: &prfPRNG{}}

	msg := []byte("fs-aead")
	ad := []byte("associated-data")

	k := make([]byte, 16)
	rand.Read(k)

	s, r, err := fs.generate(k)
	require.Nil(err)

	for i := 0; i < 10; i++ {
		ss, ct1, err := fs.send(s, msg, ad)
		require.Nil(err)
		ss, ct2, err := fs.send(ss, msg, ad)
		require.Nil(err)
		ss, ct3, err := fs.send(ss, msg, ad)
		require.Nil(err)

		rr, pt, err := fs.receive(r, ct2, ad)
		require.True(bytes.Equal(msg, pt))
		rr, pt, err = fs.receive(rr, ct1, ad)
		require.True(bytes.Equal(msg, pt))
		rr, pt, err = fs.receive(rr, ct3, ad)
		require.True(bytes.Equal(msg, pt))

		ss, ct1, err = fs.send(ss, msg, ad)
		require.Nil(err)
		rr, pt, err = fs.receive(rr, ct1, ad)
		require.True(bytes.Equal(msg, pt))

		s, r = ss, rr
	}
}
