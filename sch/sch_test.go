// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package sch

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/qantik/ratcheted/primitives/hibe"
	"github.com/qantik/ratcheted/primitives/signature"
)

var (
	fsg    = signature.NewBellare()
	gentry = hibe.NewGentry()

	sch = NewSCh(fsg, gentry)

	msg = []byte{
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
	}
)

func TestSCh_Alternating(t *testing.T) {
	require := require.New(t)

	s := NewSCh(signature.NewBellare(), hibe.NewGentry())

	alice, bob, err := s.Init()
	require.Nil(err)

	for i := 0; i < 10; i++ {
		m, err := s.Send(alice, msg, msg)
		require.Nil(err)

		pt, err := s.Receive(bob, msg, m)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))

		m, err = s.Send(bob, msg, msg)
		require.Nil(err)

		pt, err = s.Receive(alice, msg, m)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}
}

func TestSCh_Unidirectional(t *testing.T) {
	require := require.New(t)

	s := NewSCh(signature.NewBellare(), hibe.NewGentry())

	alice, bob, err := s.Init()
	require.Nil(err)

	for i := 0; i < 10; i++ {
		ct, err := sch.Send(alice, msg, msg)
		require.Nil(err)

		pt, err := sch.Receive(bob, msg, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}

	for i := 0; i < 10; i++ {
		ct, err := sch.Send(bob, msg, msg)
		require.Nil(err)

		pt, err := sch.Receive(alice, msg, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}
}

func TestSCh_DefUnidirectional(t *testing.T) {
	require := require.New(t)

	s := NewSCh(signature.NewBellare(), hibe.NewGentry())

	alice, bob, err := s.Init()
	require.Nil(err)

	var cts [10][]byte
	for i := 0; i < 10; i++ {
		ct, err := sch.Send(alice, msg, msg)

		require.Nil(err)
		cts[i] = ct
	}

	for i := 0; i < 10; i++ {
		ct, err := sch.Send(bob, msg, msg)
		require.Nil(err)

		pt, err := sch.Receive(alice, msg, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}

	for i := 0; i < 10; i++ {
		pt, err := sch.Receive(bob, msg, cts[i])
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}
}
