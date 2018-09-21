// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package r1

import "testing"

func TestGentry(t *testing.T) {
	pk, sk := gen()

	for i := 0; i < 10; i++ {
		Ka, C := pk.enc()
		Kb := sk.dec(C)
		if !Ka.Equals(Kb) {
			t.Fatal("keys do not match")
		}

		ad := []byte{1, 2, 3}
		pk.update(ad)
		sk.update(ad)
	}
}
