// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package hibe

type HIBE interface {
	Setup(seed []byte) (params, root []byte, err error)
	Extract(ancestor, id []byte) ([]byte, error)
	Encrypt(params, msg []byte, id [][]byte) (c1, c2 []byte, err error)
	Decrypt(entity, c1, c2 []byte) ([]byte, error)
}
