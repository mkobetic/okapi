package okapi

type PrivateKey interface {
	Decrypt(plain []byte) (encrypted []byte, err error)
	Sign(digest []byte) (signature []byte, err error)
	Derive(pub PublicKey) (secret []byte, err error)
}

type PublicKey interface {
	Encrypt(encrypted []byte) (plain []byte, err error)
	Verify(signature []byte, digest []byte) (valid bool, err error)
}
