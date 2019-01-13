## ratcheted
`ratcheted` implements and benchmarks various novel forward-secure key agreement and
messaging protocols and aims to provide insight into the performance aspects of the different
protocols. The code base is structure as a library as to enable integration in other projects.

For the `ratcheted` library reference, see [the documentation](https://godoc.org/github.com/qantik/ratcheted).  

## Requirements
 - go (with set $GOPATH)
 - [dep](https://github.com/golang/dep)
 - [pbc](https://github.com/Nik-U/pbc) (Standford Pairing-Based Cryptography Library)

## Installation
```
$ go get -u github.com/qantik/ratcheted
$ cd ${GOPATH}/src/github.com/qantik/ratcheted

# On Linux make sure that the pbc libary path is set.
# export LIBRARY_PATH=$LIBRARY_PATH:/usr/local/lib
# export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib 

$ dep ensure
$ go test -v ./...
````

## Benchmarks
```
# To run the BRKE benchmarks, same for the other protocols.
$ cd pt

# Turn off Go garbage collection.
$ GOGC=off

# Runtime benchmarks.
$ go test -bench=. -run=Benchmark

# Message and state size benchmarks.
$ go run size.go
```

## Project Structure
- `./acd` Double Ratchet protocol by [Alwen, Coretti & Dodis](https://eprint.iacr.org/2018/1037).
- `./dv` BARK protocol by [Durak & Vaudenay](https://eprint.iacr.org/2018/889).
- `./jmm` Secure Channel protocol by [Jost, Maurer & Mularczyk](https://eprint.iacr.org/2018/954).
- `./js` Secure Channel protocol by [Jaeger & Stepanovs](https://eprint.iacr.org/2018/553).
- `./pr` BRKE protocol by [Poettering & Rösler](https://eprint.iacr.org/2018/296).
- `./primitives` contains the implementation of various cryptographic primitives as needed by the protocols.
- `./report` and `./slides` contain the `TeX` sources for the project write-up and the accompanying slides.
