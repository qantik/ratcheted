package r2

import (
	"crypto/elliptic"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLa(t *testing.T) {
	c := elliptic.P256()

	ecies := NewECIES(c)
	ecdsa := NewECDSA(c)
	sc := NewSigncryption(ecies, ecdsa)

	sks, skr, err := sc.GenerateSignKeys()
	require.Nil(t, err)
	pks, pkr, err := sc.GenerateCipherKeys()
	require.Nil(t, err)

	msg := make([]byte, 3)
	msg[0] = 1
	msg[1] = 2
	msg[2] = 3

	ct, err := sc.Signcrypt(sks, pkr, msg)
	require.Nil(t, err)

	pt, err := sc.Unsigncrypt(skr, pks, ct)
	require.Nil(t, err)
	fmt.Println(pt, err)
}
