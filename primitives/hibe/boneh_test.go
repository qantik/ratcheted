// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package hibe

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBoneh(t *testing.T) {
	require := require.New(t)

	b := NewBoneh()

	var seed [128]byte
	rand.Read(seed[:])

	params, root, err := b.Setup(seed[:])
	require.Nil(err)

	id1 := [][]byte{[]byte{1}}
	id2 := [][]byte{[]byte{2}}
	id21 := [][]byte{[]byte{2}, []byte{2, 1}}
	id11 := [][]byte{[]byte{1}, []byte{1, 1}}
	id111 := [][]byte{[]byte{1}, []byte{1, 1}, []byte{1, 1, 1}}
	id1111 := [][]byte{[]byte{1}, []byte{1, 1}, []byte{1, 1, 1}, []byte{1, 1, 1, 1}}

	msg := []byte("hello")

	// Message to id1
	e1, err := b.Extract(root, id1[0])
	require.Nil(err)

	c1, c2, err := b.Encrypt(params, msg, id1)
	require.Nil(err)

	pt, err := b.Decrypt(e1, c1, c2)
	require.Nil(err)
	require.True(bytes.Equal(msg, pt))

	// Message to id2
	e2, err := b.Extract(root, id2[0])
	require.Nil(err)

	c1, c2, err = b.Encrypt(params, msg, id2)
	require.Nil(err)

	pt, err = b.Decrypt(e2, c1, c2)
	require.Nil(err)
	require.True(bytes.Equal(msg, pt))

	// Message to id21
	e21, err := b.Extract(e2, id21[1])
	require.Nil(err)

	c1, c2, err = b.Encrypt(params, msg, id21)
	require.Nil(err)

	pt, err = b.Decrypt(e21, c1, c2)
	require.Nil(err)
	require.True(bytes.Equal(msg, pt))

	// Message to id11
	e11, err := b.Extract(e1, id11[1])
	require.Nil(err)

	c1, c2, err = b.Encrypt(params, msg, id11)
	require.Nil(err)

	pt, err = b.Decrypt(e11, c1, c2)
	require.Nil(err)
	require.True(bytes.Equal(msg, pt))

	// Message to id111
	e111, err := b.Extract(e11, id111[2])
	require.Nil(err)

	c1, c2, err = b.Encrypt(params, msg, id111)
	require.Nil(err)

	pt, err = b.Decrypt(e111, c1, c2)
	require.Nil(err)
	require.True(bytes.Equal(msg, pt))

	// Message to id1111
	e1111, err := b.Extract(e111, id1111[3])
	require.Nil(err)

	c1, c2, err = b.Encrypt(params, msg, id1111)
	require.Nil(err)

	pt, err = b.Decrypt(e1111, c1, c2)
	require.Nil(err)
	require.True(bytes.Equal(msg, pt))

}
