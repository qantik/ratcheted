// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package r1

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSRKE(t *testing.T) {
	require := require.New(t)

	gentry := NewGentryKEM(rand.Reader)
	lamport := NewLamportOTS(rand.Reader, sha256.New)
	srke := NewSRKE(gentry, lamport)

	s, r := srke.init()
	ad := []byte{1, 2, 3}

	for i := 0; i < 10; i++ {
		ka1, C1 := srke.senderSend(s, ad)
		ka2, C2 := srke.senderSend(s, ad)

		Cp1 := srke.receiverSend(r, ad)
		Cp2 := srke.receiverSend(r, ad)
		srke.senderReceive(s, ad, Cp1)
		srke.senderReceive(s, ad, Cp2)

		kb1 := srke.receiverReceive(r, ad, C1)
		require.True(bytes.Equal(ka1, kb1))

		kb2 := srke.receiverReceive(r, ad, C2)
		require.True(bytes.Equal(ka2, kb2))
	}
}
