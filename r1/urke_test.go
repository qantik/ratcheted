package r1

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestURKE(t *testing.T) {
	require := require.New(t)

	snd, rcv := urkeInit()

	ad := []byte{1, 2, 3}

	for i := 0; i < 100; i++ {
		ka, C := snd.send(ad)
		kb := rcv.receive(ad, C)
		require.Equal(0, bytes.Compare(ka, kb))
	}
}
