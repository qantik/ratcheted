// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package sch

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSCh_Synchronous(t *testing.T) {
	require := require.New(t)

	s := NewSCh()

	ua, ub, err := s.Init()
	require.Nil(err)

	msg := []byte("SCh")
	ad := []byte("associated")

	for i := 0; i < 10; i++ {
		m, err := s.Send(ua, ad, msg)
		require.Nil(err)

		pt, err := s.Receive(ub, ad, m)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))

		m, err = s.Send(ub, ad, msg)
		require.Nil(err)

		pt, err = s.Receive(ua, ad, m)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}
}

func TestSCh_Asynchronous(t *testing.T) {
	require := require.New(t)

	s := NewSCh()

	ua, ub, err := s.Init()
	require.Nil(err)

	msg := []byte("SCh")
	ad := []byte("associated")

	for i := 0; i < 10; i++ {
		m1, err := s.Send(ua, ad, msg)
		require.Nil(err)

		m2, err := s.Send(ub, ad, msg)
		require.Nil(err)

		pt, err := s.Receive(ub, ad, m1)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))

		pt, err = s.Receive(ua, ad, m2)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}
}
