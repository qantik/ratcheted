package hibe

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGentry(t *testing.T) {
	require := require.New(t)

	gentry := NewGentry()

	// master
	msk, _, err := gentry.GenerateKeys()
	require.Nil(err)

	// first child
	id1 := []byte{100}
	sk1, err := gentry.Extract(msk, id1)
	require.Nil(err)

	// second child
	id2 := []byte{200}
	sk2, err := gentry.Extract(msk, id2)
	require.Nil(err)

	id3 := []byte{200, 250}
	sk3, err := gentry.Extract(sk2, id3)
	require.Nil(err)

	id4 := []byte{200, 250, 255}
	sk4, err := gentry.Extract(sk3, id4)
	require.Nil(err)

	// send 1 to 2
	msg := []byte{1, 2, 3, 4}
	c, v, err := gentry.Encrypt(msg, id2)
	require.Nil(err)

	m, err := gentry.Decrypt(sk2, c, v)
	require.Nil(err)
	fmt.Println(m)

	// send 1 to 3
	msg = []byte{1, 2, 3, 4, 5}
	c, v, err = gentry.Encrypt(msg, id3)
	require.Nil(err)

	m, err = gentry.Decrypt(sk3, c, v)
	require.Nil(err)
	fmt.Println(m)

	// send 3 to 1
	msg = []byte{1, 2, 3, 4, 5, 6, 7}
	c, v, err = gentry.Encrypt(msg, id1)
	require.Nil(err)

	m, err = gentry.Decrypt(sk1, c, v)
	require.Nil(err)
	fmt.Println(m)

	// send 2 to 4
	msg = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	c, v, err = gentry.Encrypt(msg, id4)
	require.Nil(err)

	m, err = gentry.Decrypt(sk4, c, v)
	require.Nil(err)
	fmt.Println(m)

}
