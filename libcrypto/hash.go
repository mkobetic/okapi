package libcrypto

// #cgo LDFLAGS:  -L/usr/local/opt/openssl/lib -lcrypto
// #cgo CFLAGS: -I/usr/local/opt/openssl/include
// #include <openssl/evp.h>
import "C"
import (
	"errors"
	"github.com/mkobetic/okapi"
	"unsafe"
)

func init() {
	okapi.MD4.Use(func() okapi.Hash { return NewHash(C.EVP_md4()) })
	okapi.MD5.Use(func() okapi.Hash { return NewHash(C.EVP_md5()) })
	okapi.SHA1.Use(func() okapi.Hash { return NewHash(C.EVP_sha1()) })
	okapi.SHA224.Use(func() okapi.Hash { return NewHash(C.EVP_sha224()) })
	okapi.SHA256.Use(func() okapi.Hash { return NewHash(C.EVP_sha256()) })
	okapi.SHA384.Use(func() okapi.Hash { return NewHash(C.EVP_sha384()) })
	okapi.SHA512.Use(func() okapi.Hash { return NewHash(C.EVP_sha512()) })
	okapi.RIPEMD160.Use(func() okapi.Hash { return NewHash(C.EVP_ripemd160()) })
}

type Hash struct {
	digest []byte
	ctx    *C.EVP_MD_CTX
	md     *C.EVP_MD // libcrypto constant
}

var (
	MD5    = C.EVP_md5()
	SHA1   = C.EVP_sha1()
	SHA256 = C.EVP_sha256()
	SHA512 = C.EVP_sha512()
)

func NewHash(algorithm *C.EVP_MD) okapi.Hash {
	h := &Hash{md: algorithm}
	h.ctx = new(C.EVP_MD_CTX)
	C.EVP_MD_CTX_init(h.ctx)
	check(C.EVP_DigestInit_ex(h.ctx, algorithm, nil))
	return h
}

func (h *Hash) Size() int {
	return int(C.EVP_MD_size(h.md))
}

func (h *Hash) BlockSize() int {
	return int(C.EVP_MD_block_size(h.md))
}

func (h *Hash) Reset() {
	check(C.EVP_DigestInit_ex(h.ctx, nil, nil))
}

func (h *Hash) Clone() okapi.Hash {
	ctx2 := new(C.EVP_MD_CTX)
	C.EVP_MD_CTX_init(ctx2)
	C.EVP_MD_CTX_copy_ex(ctx2, h.ctx)
	return &Hash{md: h.md, ctx: ctx2}
}

func (h *Hash) Digest() []byte {
	if h.digest != nil {
		return h.digest
	}
	h.digest = make([]byte, h.Size())
	check(C.EVP_DigestFinal_ex(h.ctx, (*C.uchar)(&h.digest[0]), nil))
	return h.digest
}

func (h *Hash) Write(data []byte) (int, error) {
	if h.digest != nil {
		return 0, errors.New("Cannot write into finalized hash")
	}
	check(C.EVP_DigestUpdate(h.ctx, unsafe.Pointer(&data[0]), C.size_t(len(data))))
	return len(data), nil
}

func (h *Hash) Close() {
	if h.ctx == nil {
		return
	}
	defer func() {
		h.ctx = nil
	}()
	C.EVP_MD_CTX_cleanup(h.ctx)
}
