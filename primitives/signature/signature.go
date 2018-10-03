package signature

type Signature interface {
	Generate() (pk, sk []byte, err error)
	Sign(sk, msg []byte) ([]byte, error)
	Verify(pk, msg, sig []byte) error
}
