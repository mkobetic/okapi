// +build !windows

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
	okapi.MD4 = MD4
	okapi.MD5 = MD5
	okapi.SHA1 = SHA1
	okapi.SHA224 = SHA224
	okapi.SHA256 = SHA256
	okapi.SHA384 = SHA384
	okapi.SHA512 = SHA512
	okapi.RIPEMD160 = RIPEMD160
}

type Hash struct {
	digest []byte
	ctx    *C.EVP_MD_CTX
	md     *C.EVP_MD // libcrypto constant
}

func MD4() okapi.Hash       { return NewHash(C.EVP_md4()) }
func MD5() okapi.Hash       { return NewHash(C.EVP_md5()) }
func SHA1() okapi.Hash      { return NewHash(C.EVP_sha1()) }
func SHA224() okapi.Hash    { return NewHash(C.EVP_sha224()) }
func SHA256() okapi.Hash    { return NewHash(C.EVP_sha256()) }
func SHA384() okapi.Hash    { return NewHash(C.EVP_sha384()) }
func SHA512() okapi.Hash    { return NewHash(C.EVP_sha512()) }
func RIPEMD160() okapi.Hash { return NewHash(C.EVP_ripemd160()) }

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
