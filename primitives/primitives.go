// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package primitives

import "hash"

// Digest applies the hash function f on the provided data.
func Digest(f hash.Hash, data ...[]byte) []byte {
	f.Reset()
	for _, d := range data {
		f.Write(d)
	}
	return f.Sum(nil)
}
