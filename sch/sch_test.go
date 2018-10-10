// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package sch

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSCh(t *testing.T) {
	require := require.New(t)

	s := NewSCh()

	ua, ub, err := s.Init()
	require.Nil(err)

	msg := []byte("SCh")
	ad := []byte("associated")

	m, err := s.Send(ua, ad, msg)
	require.Nil(err)

	pt, err := s.Receive(ub, ad, m)
	require.Nil(err)
	require.True(bytes.Equal(msg, pt))

	m, err = s.Send(ua, ad, msg)
	require.Nil(err)

	pt, err = s.Receive(ub, ad, m)
	require.Nil(err)
	require.True(bytes.Equal(msg, pt))
}
