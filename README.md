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

## Report/Slides
The `report` and `slides` directories contain the `TeX` sources
for the project write-up and the accompanying slides. 
