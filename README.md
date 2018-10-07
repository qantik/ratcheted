## ratcheted
Proof-of-concept.

## Requirements
 - go (with set $GOPATH)
 - [dep](https://github.com/golang/dep)
 - [pbc](https://github.com/Nik-U/pbc) (Standford Pairing-Based Cryptography Library)

## Installation
```
go get -u github.com/qantik/ratcheted
cd ${GOPATH}/src/github.com/qantik/ratcheted
dep ensure
go test -v ./...
````
