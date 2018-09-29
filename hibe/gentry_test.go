package hibe

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGentry(t *testing.T) {
	g := NewGentry(160, 512)

	root, err := g.Setup()
	require.Nil(t, err)

	id1 := [][]byte{[]byte{1}}
	id2 := [][]byte{[]byte{2}}
	id21 := [][]byte{[]byte{2}, []byte{2, 1}}
	id11 := [][]byte{[]byte{1}, []byte{1, 1}}
	id111 := [][]byte{[]byte{1}, []byte{1, 1}, []byte{1, 1, 1}}
	id1111 := [][]byte{[]byte{1}, []byte{1, 1}, []byte{1, 1, 1}, []byte{1, 1, 1, 1}}

	msg := []byte("hello")

	// Message to id1
	e1, err := g.Extract(root, id1)
	require.Nil(t, err)

	ct, err := g.Encrypt(msg, id1)
	require.Nil(t, err)

	pt, err := g.Decrypt(e1, ct)
	require.Nil(t, err)
	require.True(t, bytes.Equal(msg, pt))

	// Message to id2
	e2, err := g.Extract(root, id2)
	require.Nil(t, err)

	ct, err = g.Encrypt(msg, id2)
	require.Nil(t, err)

	pt, err = g.Decrypt(e2, ct)
	require.Nil(t, err)
	require.True(t, bytes.Equal(msg, pt))

	// Message to id21
	e21, err := g.Extract(e2, id21)
	require.Nil(t, err)

	ct, err = g.Encrypt(msg, id21)
	require.Nil(t, err)

	pt, err = g.Decrypt(e21, ct)
	require.Nil(t, err)
	require.True(t, bytes.Equal(msg, pt))

	// Message to id11
	e11, err := g.Extract(e1, id11)
	require.Nil(t, err)

	ct, err = g.Encrypt(msg, id11)
	require.Nil(t, err)

	pt, err = g.Decrypt(e11, ct)
	require.Nil(t, err)
	require.True(t, bytes.Equal(msg, pt))

	// Message to id111
	e111, err := g.Extract(e11, id111)
	require.Nil(t, err)

	ct, err = g.Encrypt(msg, id111)
	require.Nil(t, err)

	pt, err = g.Decrypt(e111, ct)
	require.Nil(t, err)
	require.True(t, bytes.Equal(msg, pt))

	// Message to id1111
	e1111, err := g.Extract(e111, id1111)
	require.Nil(t, err)

	ct, err = g.Encrypt(msg, id1111)
	require.Nil(t, err)

	pt, err = g.Decrypt(e1111, ct)
	require.Nil(t, err)
	require.True(t, bytes.Equal(msg, pt))

}
