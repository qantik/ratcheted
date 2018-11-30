// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

// Package primitives bundles various cryptographic algorithms to enable modular
// usage in the messaging protocols.
package primitives

import (
	"bytes"
	"encoding/gob"
	"hash"
)

// Digest applies the hash function f on the provided data.
func Digest(f hash.Hash, data ...[]byte) []byte {
	f.Reset()
	for _, d := range data {
		f.Write(d)
	}
	return f.Sum(nil)
}

// Encode gob encodes a given structure.
func Encode(obj interface{}) ([]byte, error) {
	var buffer bytes.Buffer
	enc := gob.NewEncoder(&buffer)
	if err := enc.Encode(obj); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// Decode gob decodes a given byte array into an object.
func Decode(data []byte, obj interface{}) error {
	buffer := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buffer)
	if err := dec.Decode(obj); err != nil {
		return err
	}
	return nil
}

// Concat joins multiple bytes arrays.
func Concat(data ...[]byte) []byte {
	var res []byte
	for _, d := range data {
		res = append(res, d...)
	}
	return res
}
