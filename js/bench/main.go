// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package main

import (
	"github.com/qantik/ratcheted/js"
	"github.com/qantik/ratcheted/primitives/hibe"
	"github.com/qantik/ratcheted/primitives/signature"
)

var (
	fsg    = signature.NewBellare()
	gentry = hibe.NewGentry()

	sch = js.NewSCh(fsg, gentry)
)

var (
	msg = []byte("msg")
	ad  = []byte("ad")
)

func main() {
	time(time_alt)
	size(size_alt)
}
