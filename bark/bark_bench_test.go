// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package bark

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func alt(bark *BARK, n int, b *testing.B) {
	require := require.New(b)

	alice, bob, err := bark.Init()
	require.Nil(err)

	max := 0
	maxs := 0

	for i := 0; i < n/2; i++ {
		ka, ct, err := bark.Send(alice)
		require.Nil(err)

		if len(ct) > max {
			max = len(ct)
		}
		if alice.size() > maxs {
			maxs = alice.size()
		}
		if bob.size() > maxs {
			maxs = bob.size()
		}

		kb, err := bark.Receive(bob, ct)
		require.Nil(err)
		require.True(bytes.Equal(ka, kb))

		ka, ct, err = bark.Send(bob)
		require.Nil(err)

		if len(ct) > max {
			max = len(ct)
		}
		if alice.size() > maxs {
			maxs = alice.size()
		}
		if bob.size() > maxs {
			maxs = bob.size()
		}

		kb, err = bark.Receive(alice, ct)
		require.Nil(err)
		require.True(bytes.Equal(ka, kb))
	}

	fmt.Println("size:", max)
	fmt.Println("state:", maxs)
}

func deferredUni(bark *BARK, n int, b *testing.B) {
	require := require.New(b)

	alice, bob, err := bark.Init()
	require.Nil(err)

	max := 0

	var ks, cts [1000][]byte
	for i := 0; i < n/2; i++ {
		ka, ct, err := bark.Send(alice)
		require.Nil(err)
		if len(ct) > max {
			max = len(ct)
		}

		ks[i] = ka
		cts[i] = ct
	}

	for i := 0; i < n/2; i++ {
		ka, ct, err := bark.Send(bob)
		require.Nil(err)
		if len(ct) > max {
			max = len(ct)
		}

		kb, err := bark.Receive(alice, ct)
		require.Nil(err)
		require.True(bytes.Equal(ka, kb))
	}

	for i := 0; i < n/2; i++ {
		kb, err := bark.Receive(bob, cts[i])
		require.Nil(err)
		require.True(bytes.Equal(ks[i], kb))
	}
	fmt.Println("size", max)
}

func unidirectional(bark *BARK, n int, b *testing.B) {
	require := require.New(b)

	alice, bob, err := bark.Init()
	require.Nil(err)

	max := 0
	maxs := 0

	for i := 0; i < n/2; i++ {
		ka, ct, err := bark.Send(alice)
		require.Nil(err)
		if len(ct) > max {
			max = len(ct)
		}
		if alice.size() > maxs {
			maxs = alice.size()
		}
		if bob.size() > maxs {
			maxs = bob.size()
		}

		kb, err := bark.Receive(bob, ct)
		require.Nil(err)
		require.True(bytes.Equal(ka, kb))
	}

	for i := 0; i < n/2; i++ {
		ka, ct, err := bark.Send(bob)
		require.Nil(err)
		if len(ct) > max {
			max = len(ct)
		}

		kb, err := bark.Receive(alice, ct)
		require.Nil(err)
		require.True(bytes.Equal(ka, kb))
		if alice.size() > maxs {
			maxs = alice.size()
		}
		if bob.size() > maxs {
			maxs = bob.size()
		}
	}
	fmt.Println("size:", max)
	fmt.Println("state:", maxs)
}

func benchmarkAlt(bark *BARK, i int, b *testing.B) {
	for n := 0; n < b.N; n++ {
		alt(bark, i, b)
	}
}

func benchmarkUni(bark *BARK, i int, b *testing.B) {
	for n := 0; n < b.N; n++ {
		unidirectional(bark, i, b)
	}
}

func benchmarkDeferredUni(bark *BARK, i int, b *testing.B) {
	for n := 0; n < b.N; n++ {
		deferredUni(bark, i, b)
	}
}

//func BenchmarkAlt50(b *testing.B)  { benchmarkAlt(liteBARK, 50, b) }
//func BenchmarkAlt100(b *testing.B) { benchmarkAlt(liteBARK, 100, b) }
//func BenchmarkAlt200(b *testing.B) { benchmarkAlt(liteBARK, 200, b) }
//func BenchmarkAlt300(b *testing.B) { benchmarkAlt(liteBARK, 300, b) }
//func BenchmarkAlt400(b *testing.B) { benchmarkAlt(liteBARK, 400, b) }
//func BenchmarkAlt500(b *testing.B) { benchmarkAlt(liteBARK, 500, b) }
//func BenchmarkAlt600(b *testing.B) { benchmarkAlt(liteBARK, 600, b) }
//func BenchmarkAlt700(b *testing.B) { benchmarkAlt(liteBARK, 700, b) }
//func BenchmarkAlt800(b *testing.B) { benchmarkAlt(liteBARK, 800, b) }
//func BenchmarkAlt900(b *testing.B) { benchmarkAlt(liteBARK, 900, b) }

//
func BenchmarkUni50(b *testing.B)  { benchmarkUni(liteBARK, 50, b) }
func BenchmarkUni100(b *testing.B) { benchmarkUni(liteBARK, 100, b) }
func BenchmarkUni200(b *testing.B) { benchmarkUni(liteBARK, 200, b) }
func BenchmarkUni300(b *testing.B) { benchmarkUni(liteBARK, 300, b) }
func BenchmarkUni400(b *testing.B) { benchmarkUni(liteBARK, 400, b) }
func BenchmarkUni500(b *testing.B) { benchmarkUni(liteBARK, 500, b) }
func BenchmarkUni600(b *testing.B) { benchmarkUni(liteBARK, 600, b) }
func BenchmarkUni700(b *testing.B) { benchmarkUni(liteBARK, 700, b) }
func BenchmarkUni800(b *testing.B) { benchmarkUni(liteBARK, 800, b) }
func BenchmarkUni900(b *testing.B) { benchmarkUni(liteBARK, 900, b) }

//func BenchmarkDeferredUni50(b *testing.B)  { benchmarkDeferredUni(liteBARK, 50, b) }
//func BenchmarkDeferredUni100(b *testing.B) { benchmarkDeferredUni(liteBARK, 100, b) }
//func BenchmarkDeferredUni200(b *testing.B) { benchmarkDeferredUni(liteBARK, 200, b) }
//func BenchmarkDeferredUni300(b *testing.B) { benchmarkDeferredUni(liteBARK, 300, b) }
//func BenchmarkDeferredUni400(b *testing.B) { benchmarkDeferredUni(liteBARK, 400, b) }
//func BenchmarkDeferredUni500(b *testing.B) { benchmarkDeferredUni(liteBARK, 500, b) }
//func BenchmarkDeferredUni600(b *testing.B) { benchmarkDeferredUni(liteBARK, 600, b) }
//func BenchmarkDeferredUni700(b *testing.B) { benchmarkDeferredUni(liteBARK, 700, b) }
//func BenchmarkDeferredUni800(b *testing.B) { benchmarkDeferredUni(liteBARK, 800, b) }
//func BenchmarkDeferredUni900(b *testing.B) { benchmarkDeferredUni(liteBARK, 900, b) }
