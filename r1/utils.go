// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package r1

import "hash"

// digest is a helper function to quickly hash multiple values at once.
func digest(hash hash.Hash, data ...[]byte) []byte {
	for _, d := range data {
		hash.Write(d)
	}
	return hash.Sum(nil)
}
