// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package secmsg

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/qantik/ratcheted/primitives/encryption"
	"github.com/qantik/ratcheted/primitives/signature"
)

func secMsgAlternating(n int, b *testing.B) {
	require := require.New(b)

	hku := &hkuPKE{pke: encryption.NewECIES(elliptic.P256()), sku: &skuPKE{elliptic.P256()}}
	lamport := signature.NewLamport(rand.Reader, sha256.New)
	kus := &kuSig{lamport}

	sec := &SecMsg{hku: hku, kus: kus, sig: lamport}

	msg := []byte("secmsg")

	alice, bob, err := sec.Init()
	require.Nil(err)

	for i := 0; i < n/2; i++ {
		ct, err := sec.Send(alice, msg)
		require.Nil(err)

		pt, err := sec.Receive(bob, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))

		ct, err = sec.Send(bob, msg)
		require.Nil(err)

		pt, err = sec.Receive(alice, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}
}

func benchmarkSecMsgAlternating(i int, b *testing.B) {
	for n := 0; n < b.N; n++ {
		secMsgAlternating(i, b)
	}
}

func secMsgUnidirectional(n int, b *testing.B) {
	require := require.New(b)

	hku := &hkuPKE{pke: encryption.NewECIES(elliptic.P256()), sku: &skuPKE{elliptic.P256()}}
	lamport := signature.NewLamport(rand.Reader, sha256.New)
	kus := &kuSig{lamport}

	sec := &SecMsg{hku: hku, kus: kus, sig: lamport}

	msg := []byte("secmsg")

	alice, bob, err := sec.Init()
	require.Nil(err)

	var cts [1000][]byte
	for i := 0; i < n/2; i++ {
		ct, err := sec.Send(alice, msg)
		require.Nil(err)
		cts[i] = ct
	}

	for i := 0; i < n/2; i++ {
		ct, err := sec.Send(bob, msg)
		require.Nil(err)

		pt, err := sec.Receive(alice, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}

	for i := 0; i < n/2; i++ {
		pt, err := sec.Receive(bob, cts[i])
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}
}

func benchmarkSecMsgUnidirectional(i int, b *testing.B) {
	for n := 0; n < b.N; n++ {
		secMsgUnidirectional(i, b)
	}
}

func BenchmarkSecMsgAlternating50(b *testing.B)  { benchmarkSecMsgAlternating(50, b) }
func BenchmarkSecMsgAlternating100(b *testing.B) { benchmarkSecMsgAlternating(100, b) }
func BenchmarkSecMsgAlternating200(b *testing.B) { benchmarkSecMsgAlternating(200, b) }
func BenchmarkSecMsgAlternating300(b *testing.B) { benchmarkSecMsgAlternating(300, b) }
func BenchmarkSecMsgAlternating400(b *testing.B) { benchmarkSecMsgAlternating(400, b) }
func BenchmarkSecMsgAlternating500(b *testing.B) { benchmarkSecMsgAlternating(500, b) }
func BenchmarkSecMsgAlternating600(b *testing.B) { benchmarkSecMsgAlternating(600, b) }
func BenchmarkSecMsgAlternating700(b *testing.B) { benchmarkSecMsgAlternating(700, b) }
func BenchmarkSecMsgAlternating800(b *testing.B) { benchmarkSecMsgAlternating(800, b) }
func BenchmarkSecMsgAlternating900(b *testing.B) { benchmarkSecMsgAlternating(900, b) }

func BenchmarkSecMsgUnidirectional50(b *testing.B)  { benchmarkSecMsgUnidirectional(50, b) }
func BenchmarkSecMsgUnidirectional100(b *testing.B) { benchmarkSecMsgUnidirectional(100, b) }
func BenchmarkSecMsgUnidirectional200(b *testing.B) { benchmarkSecMsgUnidirectional(200, b) }
func BenchmarkSecMsgUnidirectional300(b *testing.B) { benchmarkSecMsgUnidirectional(300, b) }
func BenchmarkSecMsgUnidirectional400(b *testing.B) { benchmarkSecMsgUnidirectional(400, b) }
func BenchmarkSecMsgUnidirectional500(b *testing.B) { benchmarkSecMsgUnidirectional(500, b) }
func BenchmarkSecMsgUnidirectional600(b *testing.B) { benchmarkSecMsgUnidirectional(600, b) }
func BenchmarkSecMsgUnidirectional700(b *testing.B) { benchmarkSecMsgUnidirectional(700, b) }
func BenchmarkSecMsgUnidirectional800(b *testing.B) { benchmarkSecMsgUnidirectional(800, b) }
func BenchmarkSecMsgUnidirectional900(b *testing.B) { benchmarkSecMsgUnidirectional(900, b) }
